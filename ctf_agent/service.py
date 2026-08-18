"""Application service and mock-first CTF orchestration workflow."""

from __future__ import annotations

import base64
import binascii
import copy
import os
import sqlite3
import threading
import uuid
from collections import Counter
from typing import Any, Mapping

from .core import (
    ALLOWED_CATEGORIES,
    ALLOWED_STATUSES,
    BudgetManager,
    CircuitBreaker,
    PREPROCESSOR_VERSION,
    ScopeGuard,
    TierRouter,
    VERSION,
    artifact_metadata,
    classify_challenge,
    preprocess_artifact,
    scan_prompt_injection,
    stable_hash,
    utc_now,
    validate_scope_pattern,
    validate_settings_patch,
)
from .deterministic_solvers import SOLVER_VERSION, solve_crypto_sources
from .providers import ProviderError, build_solver_prompt, get_provider
from .storage import Database
from .web_solvers import WEB_SOLVER_VERSION, solve_web_sources


MAX_DESCRIPTION_CHARS = 50_000
MAX_FILES = 16
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 12 * 1024 * 1024
MAX_TEXT_ARTIFACT_SCAN = 64_000
MAX_PREPROCESS_FACTS = 24

_SAFE_ACTIONS = {"triage", "solve", "pause", "resume", "stop", "verify"}


class ServiceError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: int = 400,
        code: str = "bad_request",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = dict(details or {})

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": False,
            "error": {"code": self.code, "message": str(self)},
        }
        if self.details:
            result["error"]["details"] = self.details
        return result


class CTFService:
    """High-level API with challenge data always handled as untrusted."""

    def __init__(self, database: Database) -> None:
        self.db = database
        # Serializing state-changing solve actions keeps budget checks atomic.
        self._action_lock = threading.RLock()

    def health(self) -> dict[str, Any]:
        settings = self.db.get_settings()
        healthy = self.db.health()
        return {
            "ok": healthy,
            "status": "healthy" if healthy else "degraded",
            "version": VERSION,
            "database": "connected" if healthy else "unavailable",
            "provider": settings["provider"],
            "mock_first": settings["provider"] == "mock",
        }

    def bootstrap(self) -> dict[str, Any]:
        challenges = self.list_challenges()
        statuses = Counter(challenge["status"] for challenge in challenges)
        settings = self.settings()
        real_challenges = [challenge for challenge in challenges if not challenge["is_demo"]]
        return {
            "app": {
                "name": "CTF Agent",
                "version": VERSION,
                "mode": "demo" if not real_challenges else "operator",
                "demo_data_present": any(item["is_demo"] for item in challenges),
                "notice": "Seeded records marked Demo are illustrative and never consume budget.",
            },
            "stats": {
                "total": len(challenges),
                "real_total": len(real_challenges),
                "active": statuses["running"],
                "queued": statuses["queued"] + statuses["ready"],
                "paused": statuses["paused"],
                "solved": statuses["solved"],
                "token_spent": settings["budget"]["global_spent"],
                "global_budget": settings["global_token_budget"],
                "reserve_tokens": settings["budget"]["reserve_tokens"],
                "spendable_remaining": settings["budget"]["spendable_remaining"],
            },
            "challenges": challenges,
            "scopes": self.list_scopes(),
            "settings": settings,
            "audit": self.list_audit(limit=30),
        }

    def settings(self) -> dict[str, Any]:
        result = self.db.get_settings()
        global_budget = int(result["global_token_budget"])
        global_spent = self.db.total_token_spent()
        manager = BudgetManager(
            global_budget,
            int(result["per_challenge_token_budget"]),
            float(result["reserve_percent"]),
        )
        result["budget"] = {
            "global_spent": global_spent,
            "reserve_tokens": manager.reserve_tokens,
            "spendable_limit": global_budget - manager.reserve_tokens,
            "spendable_remaining": max(
                0, global_budget - manager.reserve_tokens - global_spent
            ),
            "reserve_protected": True,
        }
        # Report only the non-secret opt-in gate; never inspect or expose API key values.
        result["openai_enabled_by_environment"] = (
            os.environ.get("CTF_AGENT_ENABLE_OPENAI") == "1"
        )
        return result

    def patch_settings(self, patch: Mapping[str, Any]) -> dict[str, Any]:
        with self._action_lock:
            current = self.db.get_settings()
            try:
                updated = validate_settings_patch(current, patch)
            except ValueError as exc:
                raise ServiceError(str(exc), code="invalid_settings") from exc
            self.db.update_settings(updated)
            self.db.audit(
                "settings_updated",
                {"keys": sorted(patch), "provider": updated["provider"]},
            )
        return self.settings()

    def list_challenges(
        self,
        *,
        status: str | None = None,
        category: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        if status and status not in ALLOWED_STATUSES:
            raise ServiceError("invalid challenge status filter", code="invalid_filter")
        if category and category not in ALLOWED_CATEGORIES:
            raise ServiceError("invalid challenge category filter", code="invalid_filter")
        guard = ScopeGuard(self.db.list_scopes())
        return [
            self._decorate_challenge(challenge, scope_guard=guard)
            for challenge in self.db.list_challenges(
                status=status, category=category, search=search
            )
        ]

    def get_challenge(self, challenge_id: str) -> dict[str, Any]:
        challenge = self.db.get_challenge(challenge_id)
        if challenge is None:
            raise ServiceError(
                "challenge not found",
                status=404,
                code="challenge_not_found",
            )
        return self._decorate_challenge(challenge)

    def create_challenge(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ServiceError("request body must be an object")
        title = payload.get("title", payload.get("name"))
        if not isinstance(title, str) or not title.strip():
            raise ServiceError("title is required", code="invalid_challenge")
        title = title.strip()
        if len(title) > 200:
            raise ServiceError("title is too long", code="invalid_challenge")
        description = payload.get("description", "")
        if not isinstance(description, str) or len(description) > MAX_DESCRIPTION_CHARS:
            raise ServiceError(
                f"description must be at most {MAX_DESCRIPTION_CHARS} characters",
                code="invalid_challenge",
            )
        target = payload.get("target", "")
        if not isinstance(target, str) or len(target) > 500:
            raise ServiceError("target must be a short string", code="invalid_challenge")
        flag_format = payload.get("flag_format", "CTF{...}")
        if not isinstance(flag_format, str) or len(flag_format) > 120:
            raise ServiceError("flag_format must be a short string", code="invalid_challenge")
        requested_category = payload.get("category")
        if requested_category in {"", "auto", None}:
            requested_category = None
        if requested_category is not None and requested_category not in ALLOWED_CATEGORIES:
            raise ServiceError("unsupported category", code="invalid_challenge")

        settings = self.db.get_settings()
        challenge_budget = payload.get(
            "budget",
            payload.get("token_budget", settings["per_challenge_token_budget"]),
        )
        if (
            isinstance(challenge_budget, bool)
            or not isinstance(challenge_budget, int)
            or not 100 <= challenge_budget <= int(settings["global_token_budget"])
        ):
            raise ServiceError(
                "budget must be an integer between 100 and the global budget",
                code="invalid_challenge",
            )

        artifacts, artifact_text = self._decode_files(payload.get("files", []))
        metadata = [
            {key: value for key, value in item.items() if key != "content"}
            for item in artifacts
        ]
        classification = classify_challenge(
            description, metadata, requested_category=requested_category
        )
        artifact_names = "\n".join(item["name"] for item in metadata)
        scan = scan_prompt_injection(
            description + "\n" + artifact_names + "\n" + artifact_text
        )
        challenge_id = "ctf-" + uuid.uuid4().hex[:12]
        now = utc_now()
        state = {
            "objective": f"Solve {title} within authorized CTF scope.",
            "known_facts": [],
            "observations": [],
            "hypotheses": [],
            "discarded_hypotheses": [],
            "completed_actions": [],
            "failed_actions": [],
            "model_calls": 0,
            "tool_calls": 0,
            "potential_injections": list(scan.signals),
            "next_candidate_actions": ["Run deterministic triage"],
            "verification": {"status": "not_started", "reason": None},
            "circuit": CircuitBreaker.initial_state(),
        }
        route = TierRouter(settings["tier_models"]).route(
            task="triage", burn_score=scan.score
        )
        try:
            created = self.db.insert_challenge(
                {
                    "id": challenge_id,
                    "title": title,
                    "description": description,
                    "category": classification.category,
                    "category_confidence": classification.confidence,
                    "classification_reasons": list(classification.reasons),
                    "status": "queued",
                    "target": target.strip(),
                    "flag_format": flag_format,
                    "candidate_flag": None,
                    "is_demo": False,
                    "burn_score": scan.score,
                    "injection_signals": list(scan.signals),
                    "challenge_budget": challenge_budget,
                    "token_spent": 0,
                    "routing": route.as_dict(),
                    "state": state,
                    "created_at": now,
                    "updated_at": now,
                },
                artifacts,
            )
        except sqlite3.IntegrityError as exc:
            raise ServiceError("duplicate artifact name", code="duplicate_artifact") from exc
        if scan.signals:
            self.db.audit(
                "potential_prompt_injection",
                scan.as_dict(),
                challenge_id=challenge_id,
                severity="warning" if scan.hostile else "info",
            )
        return self._decorate_challenge(created)

    def _decode_files(self, raw_files: Any) -> tuple[list[dict[str, Any]], str]:
        if raw_files is None:
            raw_files = []
        if not isinstance(raw_files, list):
            raise ServiceError("files must be an array", code="invalid_files")
        if len(raw_files) > MAX_FILES:
            raise ServiceError(
                f"at most {MAX_FILES} files may be imported",
                status=413,
                code="too_many_files",
            )
        results: list[dict[str, Any]] = []
        seen_names: set[str] = set()
        text_fragments: list[str] = []
        total = 0
        for index, raw_file in enumerate(raw_files):
            if not isinstance(raw_file, Mapping):
                raise ServiceError(f"file {index} must be an object", code="invalid_files")
            name = raw_file.get("name")
            if not isinstance(name, str) or not self._safe_artifact_name(name):
                raise ServiceError(
                    f"file {index} has an unsafe name",
                    code="unsafe_filename",
                )
            if name.casefold() in seen_names:
                raise ServiceError("artifact names must be unique", code="duplicate_artifact")
            seen_names.add(name.casefold())
            encoded = raw_file.get("content_base64")
            if not isinstance(encoded, str):
                raise ServiceError(
                    f"file {name} requires content_base64",
                    code="invalid_files",
                )
            estimated_size = len(encoded) * 3 // 4
            if estimated_size > MAX_FILE_BYTES:
                raise ServiceError(
                    f"file {name} exceeds {MAX_FILE_BYTES} bytes",
                    status=413,
                    code="file_too_large",
                )
            try:
                content = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ServiceError(
                    f"file {name} contains invalid base64",
                    code="invalid_base64",
                ) from exc
            if len(content) > MAX_FILE_BYTES:
                raise ServiceError(
                    f"file {name} exceeds {MAX_FILE_BYTES} bytes",
                    status=413,
                    code="file_too_large",
                )
            total += len(content)
            if total > MAX_TOTAL_FILE_BYTES:
                raise ServiceError(
                    f"combined files exceed {MAX_TOTAL_FILE_BYTES} bytes",
                    status=413,
                    code="files_too_large",
                )
            media_type = raw_file.get("media_type")
            if media_type is not None and (
                not isinstance(media_type, str) or len(media_type) > 120
            ):
                raise ServiceError("invalid media_type", code="invalid_files")
            item = artifact_metadata(name, content, media_type)
            item["id"] = "artifact-" + uuid.uuid4().hex[:12]
            item["content"] = content
            results.append(item)
            if item["kind"] == "text" and len(content) <= MAX_TEXT_ARTIFACT_SCAN:
                text_fragments.append(content.decode("utf-8", errors="replace"))
        return results, "\n".join(text_fragments)[:MAX_DESCRIPTION_CHARS]

    @staticmethod
    def _safe_artifact_name(name: str) -> bool:
        if not name or len(name) > 160 or name in {".", ".."}:
            return False
        if name.startswith(".") or "/" in name or "\\" in name or "\x00" in name:
            return False
        if ".." in name or any(ord(char) < 32 for char in name):
            return False
        return True

    def run_action(
        self,
        challenge_id: str,
        action: str,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if action not in _SAFE_ACTIONS:
            raise ServiceError("unknown action", status=404, code="unknown_action")
        body = dict(payload or {})
        with self._action_lock:
            challenge = self.get_challenge(challenge_id)
            if action == "triage":
                updated = self._triage(challenge)
            elif action == "solve":
                updated = self._solve(challenge, body)
            elif action == "verify":
                updated = self._verify(challenge, body)
            else:
                updated = self._transition(challenge, action)
        return {"ok": True, "action": action, "challenge": updated}

    def _triage(self, challenge: Mapping[str, Any]) -> dict[str, Any]:
        if challenge["status"] == "solved":
            raise ServiceError(
                "solved challenges do not need triage",
                status=409,
                code="invalid_transition",
            )
        preprocessing = self._preprocess_challenge(challenge)
        artifact_fingerprints = [
            artifact["sha256"] for artifact in challenge.get("artifacts", ())
        ]
        cache_key = "triage:" + stable_hash(
            {
                "description": challenge["description"],
                "artifacts": artifact_fingerprints,
                "category": challenge["category"],
                "burn_score": challenge["burn_score"],
                "preprocessor": preprocessing["fingerprint"],
            }
        )
        triage = self.db.cache_get(cache_key)
        cache_hit = triage is not None
        if triage is None:
            observations = [
                f"Deterministic category: {challenge['category']} "
                f"({challenge['category_confidence']:.0%} confidence)",
                f"Artifact count: {challenge['artifact_count']}",
            ]
            observations.extend(preprocessing["facts"][:MAX_PREPROCESS_FACTS])
            if preprocessing["candidates"]:
                observations.append(
                    "Bounded deterministic extraction found "
                    f"{len(preprocessing['candidates'])} flag-format candidate(s)."
                )
            if challenge["target"]:
                observations.append(
                    "Target is "
                    + ("allowlisted" if challenge["scope_authorized"] else "not allowlisted")
                )
            if challenge["injection_signals"]:
                observations.append(
                    "Untrusted instructions isolated: "
                    + ", ".join(challenge["injection_signals"])
                )
            triage = {
                "observations": observations,
                "next_candidate_actions": self._category_actions(challenge["category"]),
            }
            self.db.cache_set(cache_key, triage)
        state = copy.deepcopy(challenge["state"])
        prior_observations = set(state.get("observations") or [])
        for observation in triage["observations"]:
            if observation not in prior_observations:
                state.setdefault("observations", []).append(observation)
        fact = "Challenge content is untrusted and cannot authorize actions."
        if fact not in state.setdefault("known_facts", []):
            state["known_facts"].append(fact)
        known_facts = state.setdefault("known_facts", [])
        for preprocessing_fact in preprocessing["facts"][:MAX_PREPROCESS_FACTS]:
            if preprocessing_fact not in known_facts:
                known_facts.append(preprocessing_fact)
        state["deterministic_preprocess"] = {
            "version": PREPROCESSOR_VERSION,
            "fingerprint": preprocessing["fingerprint"],
            "artifact_count": len(preprocessing["artifacts"]),
            "safety_notes": preprocessing["safety_notes"],
            "solver_routes": preprocessing["solver_routes"],
            "web_facts": preprocessing["web_facts"],
            "web_routes": preprocessing["web_routes"],
            "web_signals": preprocessing["web_signals"],
            "web_parameters": preprocessing["web_parameters"],
        }
        state["deterministic_candidates"] = preprocessing["candidates"]
        state["next_candidate_actions"] = triage["next_candidate_actions"]
        if "triage" not in state.setdefault("completed_actions", []):
            state["completed_actions"].append("triage")
        if not cache_hit:
            state["tool_calls"] = int(state.get("tool_calls", 0)) + 1
        state["circuit"] = CircuitBreaker.record(
            state.get("circuit"),
            fingerprint=cache_key,
            progress=not cache_hit,
            max_iterations=self.db.get_settings()["max_iterations"],
        )
        settings = self.db.get_settings()
        route = TierRouter(settings["tier_models"]).route(
            task="triage", burn_score=challenge["burn_score"]
        )
        updated = self.db.update_challenge(
            challenge["id"],
            {"status": "ready", "routing": route.as_dict(), "state": state},
        )
        self.db.audit(
            "triage_completed",
            {
                "cache_hit": cache_hit,
                "category": challenge["category"],
                "burn_score": challenge["burn_score"],
                "model_called": False,
                "preprocess_cache_hit": preprocessing["cache_hit"],
                "candidate_count": len(preprocessing["candidates"]),
                "web_route_count": len(preprocessing["web_routes"]),
                "web_signal_count": len(preprocessing["web_signals"]),
            },
            challenge_id=challenge["id"],
        )
        return self._decorate_challenge(updated)

    @staticmethod
    def _category_actions(category: str) -> list[str]:
        actions = {
            "web": ["Map local routes and trust boundaries", "Inspect auth and input validation"],
            "pwn": ["Inspect ELF hardening and imports", "Map attacker-controlled input"],
            "reverse": ["Inspect strings, imports, and entry points", "Locate validation branches"],
            "crypto": ["Extract exact parameters", "Test simple invariant violations"],
            "forensics": ["Summarize artifact metadata", "Isolate anomalous streams or bytes"],
            "osint": ["Extract distinctive public clues", "Constrain identity, place, and time"],
            "hardware": ["Inventory firmware and interfaces", "Decode the smallest signal sample"],
            "stego": ["Check metadata and trailing bytes", "Compare channels and bit planes"],
            "misc": ["Inspect the smallest unexplained artifact"],
        }
        return actions.get(category, actions["misc"])

    def _solve(
        self,
        challenge: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        if challenge["status"] in {"paused", "stopped", "solved", "rejected"}:
            raise ServiceError(
                f"cannot solve a {challenge['status']} challenge",
                status=409,
                code="invalid_transition",
            )
        if "triage" not in challenge.get("state", {}).get("completed_actions", []):
            challenge = self._triage(challenge)
        state = copy.deepcopy(challenge["state"])
        circuit = state.get("circuit") or CircuitBreaker.initial_state()
        if circuit.get("tripped"):
            raise ServiceError(
                "circuit breaker is tripped",
                status=409,
                code="circuit_breaker",
                details={"reason": circuit.get("trip_reason")},
            )
        complexity = payload.get("complexity")
        if complexity is None:
            complexity = min(
                0.85,
                0.32
                + challenge["artifact_count"] * 0.06
                + (0.12 if challenge["category"] in {"pwn", "reverse", "hardware"} else 0),
            )
        if isinstance(complexity, bool) or not isinstance(complexity, (int, float)):
            raise ServiceError("complexity must be a number", code="invalid_action")
        complexity = max(0.0, min(float(complexity), 1.0))
        settings = self.db.get_settings()
        cheaper_failed_input = payload.get("cheaper_failed", False)
        if not isinstance(cheaper_failed_input, bool):
            raise ServiceError("cheaper_failed must be a boolean", code="invalid_action")
        cheaper_failed = bool(state.get("failed_actions")) or cheaper_failed_input
        router = TierRouter(settings["tier_models"])
        deterministic_candidate = self._unique_deterministic_candidate(state)
        route = router.route(
            task="triage" if deterministic_candidate else "solve",
            complexity=complexity,
            burn_score=challenge["burn_score"],
            cheaper_failed=cheaper_failed,
            large_calls=int(circuit.get("large_model_calls", 0)),
            max_large_calls=settings["max_large_model_calls"],
        )
        budget = BudgetManager(
            settings["global_token_budget"],
            challenge["budget"]["allocated"],
            settings["reserve_percent"],
        )
        global_spent = self.db.total_token_spent()
        allow_reserve = payload.get("allow_reserve", False)
        if not isinstance(allow_reserve, bool):
            raise ServiceError("allow_reserve must be a boolean", code="invalid_action")
        reserve_justification = payload.get("reserve_justification", "")
        if allow_reserve and (
            not isinstance(reserve_justification, str)
            or not 12 <= len(reserve_justification.strip()) <= 500
        ):
            raise ServiceError(
                "reserve use requires a 12–500 character justification",
                code="reserve_justification_required",
            )
        decision = budget.authorize(
            route.estimated_tokens,
            global_spent=global_spent,
            challenge_spent=challenge["budget"]["spent"],
            allow_reserve=allow_reserve is True,
        )
        if not decision.allowed:
            self.db.audit(
                "budget_blocked",
                decision.as_dict(),
                challenge_id=challenge["id"],
                severity="warning",
            )
            raise ServiceError(
                "token budget blocked this action",
                status=409,
                code="budget_exceeded",
                details=decision.as_dict(),
            )
        if allow_reserve:
            self.db.audit(
                "reserve_use_authorized",
                {
                    "estimated_tokens": route.estimated_tokens,
                    "justification": reserve_justification.strip(),
                },
                challenge_id=challenge["id"],
                severity="warning",
            )

        network_requested = payload.get("network", False)
        if not isinstance(network_requested, bool):
            raise ServiceError("network must be a boolean", code="invalid_action")
        if network_requested:
            if not settings["network_enabled"]:
                raise ServiceError(
                    "network execution is disabled",
                    status=403,
                    code="network_disabled",
                )
            if not challenge["target"] or not challenge["scope_authorized"]:
                self.db.audit(
                    "scope_blocked",
                    {"target": challenge["target"]},
                    challenge_id=challenge["id"],
                    severity="warning",
                )
                raise ServiceError(
                    "target is not explicitly allowlisted",
                    status=403,
                    code="scope_denied",
                )

        if deterministic_candidate:
            model_content = {
                "hypothesis": "A flag-format candidate was recovered by bounded deterministic artifact inspection.",
                "confidence": 0.95,
                "evidence": [deterministic_candidate["evidence_id"]],
                "next_action": "Replay deterministic artifact verification before operator submission.",
                "estimated_cost": "none",
                "notice": "No model was called; candidate remains unsubmitted.",
            }
            charged_tokens = 0
            provider_name = "deterministic"
            state["tool_calls"] = int(state.get("tool_calls", 0)) + 1
        elif route.tier == "tool":
            model_content = {
                "hypothesis": (
                    "Adversarial instructions are isolated; continue only with bounded "
                    "deterministic artifact inspection."
                    if challenge["burn_score"] >= 0.60
                    else "Deterministic inspection remains the cheapest useful action."
                ),
                "confidence": 0.82,
                "evidence": challenge["injection_signals"][:3],
                "next_action": (
                    state.get("next_candidate_actions")
                    or self._category_actions(challenge["category"])
                )[0],
                "estimated_cost": "none",
                "notice": "No model was called.",
            }
            charged_tokens = 0
            provider_name = "deterministic"
            state["tool_calls"] = int(state.get("tool_calls", 0)) + 1
        else:
            output_cap = min(
                int(settings["max_model_output_tokens"]),
                max(64, route.estimated_tokens // 4),
            )
            prompt_cap_chars = max(1_000, (route.estimated_tokens - output_cap) * 2)
            prompt = build_solver_prompt(challenge, max_chars=prompt_cap_chars)
            # Repeated clicks/retries are common when a provider is slow.  Reuse a
            # bounded result for the same challenge, route, and stable evidence
            # instead of paying for (or waiting on) the same model call again.
            # Dynamic hypothesis/action history is intentionally excluded from the
            # key so a no-progress retry deduplicates, while new known facts still
            # produce a fresh request.
            model_cache_key = "model:" + stable_hash(
                {
                    "version": 1,
                    "challenge_id": challenge["id"],
                    "provider": settings["provider"],
                    "route": route.as_dict(),
                    "category": challenge["category"],
                    "description": challenge["description"],
                    "known_facts": state.get("known_facts", []),
                    "burn_score": challenge["burn_score"],
                    "max_output_tokens": output_cap,
                }
            )
            cached_model = self.db.cache_get(model_cache_key)
            model_cache_hit = isinstance(cached_model, Mapping) and isinstance(
                cached_model.get("content"), Mapping
            )
            if model_cache_hit:
                model_content = dict(cached_model["content"])
                charged_tokens = 0
                provider_name = "cache"
                state["tool_calls"] = int(state.get("tool_calls", 0)) + 1
            else:
                # Provider construction may load an SDK or inspect credentials;
                # defer it until the cache has proved a real call is necessary.
                provider = get_provider(settings["provider"])
                try:
                    result = provider.analyze(
                        model=route.model,
                        prompt=prompt,
                        max_output_tokens=output_cap,
                        context={
                            "category": challenge["category"],
                            "known_facts": state.get("known_facts", []),
                        },
                        reasoning_effort={
                            "luna": "low",
                            "terra": "medium",
                            "sol": "high",
                        }[route.tier],
                    )
                except ProviderError as exc:
                    fingerprint = stable_hash(
                        {"route": route.as_dict(), "state": state.get("known_facts", [])}
                    )
                    state["model_calls"] = int(state.get("model_calls", 0)) + 1
                    state.setdefault("failed_actions", []).append(
                        {"action": "model_analysis", "reason": str(exc)[:300]}
                    )
                    state["circuit"] = CircuitBreaker.record(
                        circuit,
                        fingerprint=fingerprint,
                        progress=False,
                        failed=True,
                        used_large_model=route.tier == "sol",
                        max_iterations=settings["max_iterations"],
                    )
                    self.db.update_challenge(
                        challenge["id"],
                        {
                            "status": "stopped"
                            if state["circuit"]["tripped"]
                            else "ready",
                            "routing": route.as_dict(),
                            "state": state,
                        },
                    )
                    self.db.audit(
                        "provider_error",
                        {"provider": settings["provider"], "message": str(exc)[:300]},
                        challenge_id=challenge["id"],
                        severity="error",
                    )
                    raise ServiceError(
                        str(exc),
                        status=502,
                        code="provider_error",
                    ) from exc
                model_content = result.content
                charged_tokens = result.total_tokens or route.estimated_tokens
                provider_name = result.provider
                state["model_calls"] = int(state.get("model_calls", 0)) + 1
                self.db.cache_set(
                    model_cache_key,
                    {
                        "content": model_content,
                        "provider": result.provider,
                        "model": result.model,
                    },
                )

        hypothesis = self._bounded_text(
            model_content.get("hypothesis") or model_content.get("analysis"),
            1_000,
        )
        if not hypothesis:
            hypothesis = "No usable hypothesis was returned."
        previous = {
            item.get("text") if isinstance(item, Mapping) else str(item)
            for item in state.setdefault("hypotheses", [])
        }
        progress = hypothesis not in previous
        if progress:
            state["hypotheses"].append(
                {
                    "text": hypothesis,
                    "confidence": self._confidence(model_content.get("confidence")),
                    "tier": route.tier,
                    "created_at": utc_now(),
                }
            )
        next_action = self._bounded_text(model_content.get("next_action"), 500)
        if next_action:
            state["next_candidate_actions"] = [next_action]
        state.setdefault("completed_actions", []).append(
            {"action": "solve_iteration", "tier": route.tier, "at": utc_now()}
        )
        fingerprint = stable_hash({"tier": route.tier, "hypothesis": hypothesis})
        state["circuit"] = CircuitBreaker.record(
            circuit,
            fingerprint=fingerprint,
            progress=progress,
            used_large_model=route.tier == "sol",
            max_iterations=settings["max_iterations"],
        )
        new_status = (
            "stopped"
            if state["circuit"]["tripped"]
            else "ready"
            if deterministic_candidate
            else "running"
        )
        updated = self.db.update_challenge(
            challenge["id"],
            {
                "status": new_status,
                "token_spent": challenge["budget"]["spent"] + charged_tokens,
                "candidate_flag": challenge.get("candidate_flag")
                or (deterministic_candidate or {}).get("value"),
                "routing": {
                    **route.as_dict(),
                    "provider": provider_name,
                    "complexity": round(complexity, 2),
                },
                "state": state,
            },
        )
        self.db.audit(
            "solve_iteration",
            {
                "route": route.as_dict(),
                "charged_tokens": charged_tokens,
                "model_cache_hit": model_cache_hit if route.tier != "tool" else False,
                "progress": progress,
                "circuit": state["circuit"],
                "network_used": False,
                "deterministic_candidate": bool(deterministic_candidate),
            },
            challenge_id=challenge["id"],
            severity="warning" if challenge["burn_score"] >= 0.60 else "info",
        )
        return self._decorate_challenge(updated)

    def _verify(
        self,
        challenge: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        candidate = payload.get("candidate_flag", challenge.get("candidate_flag"))
        if not isinstance(candidate, str) or not candidate.strip():
            raise ServiceError("candidate_flag is required", code="invalid_candidate")
        candidate = candidate.strip()
        if len(candidate) > 500 or any(ord(char) < 32 for char in candidate):
            raise ServiceError("candidate_flag is invalid", code="invalid_candidate")
        format_valid = self._flag_matches(candidate, challenge["flag_format"])
        reproduced = payload.get("reproduced", False)
        if not isinstance(reproduced, bool):
            raise ServiceError("reproduced must be a boolean", code="invalid_action")
        evidence = payload.get("evidence", [])
        if evidence is None:
            evidence = []
        if not isinstance(evidence, list) or len(evidence) > 20:
            raise ServiceError("evidence must be a short array", code="invalid_action")
        clean_evidence = [self._bounded_text(item, 500) for item in evidence]
        clean_evidence = [item for item in clean_evidence if item]

        replay = self._preprocess_challenge(challenge, force_refresh=True)
        deterministic_evidence = [
            item
            for item in replay["candidates"]
            if item.get("value") == candidate
        ]

        if not format_valid:
            verification_status = "rejected"
            reason = "candidate does not match the configured flag format"
            status = "ready"
        elif deterministic_evidence:
            verification_status = "verified"
            reason = "format and bounded deterministic replay against original artifact bytes passed"
            status = "solved"
        else:
            verification_status = "needs_evidence"
            reason = (
                "format is valid, but client-provided reproduction claims are not independent "
                "verification; run a bounded verifier or attach artifact-derived evidence"
            )
            status = challenge["status"] if challenge["status"] != "queued" else "ready"
        state = copy.deepcopy(challenge["state"])
        state["tool_calls"] = int(state.get("tool_calls", 0)) + 1
        state["verification"] = {
            "status": verification_status,
            "reason": reason,
            "format_valid": format_valid,
            "client_claimed_reproduction": reproduced,
            "client_evidence": clean_evidence,
            "deterministic_evidence": deterministic_evidence,
            "checked_at": utc_now(),
        }
        if verification_status == "verified":
            state.setdefault("completed_actions", []).append("independent_verification")
            state["next_candidate_actions"] = []
        updated = self.db.update_challenge(
            challenge["id"],
            {
                "status": status,
                "candidate_flag": candidate,
                "state": state,
                "routing": TierRouter(
                    self.db.get_settings()["tier_models"]
                ).route(task="verify_format").as_dict(),
            },
        )
        self.db.audit(
            "flag_verification",
            {
                "status": verification_status,
                "format_valid": format_valid,
                "client_claimed_reproduction": reproduced,
                "client_evidence_count": len(clean_evidence),
                "deterministic_evidence_count": len(deterministic_evidence),
            },
            challenge_id=challenge["id"],
            severity="info" if verification_status == "verified" else "warning",
        )
        return self._decorate_challenge(updated)

    @staticmethod
    def _flag_matches(candidate: str, flag_format: str) -> bool:
        if not flag_format:
            return bool(candidate)
        if "..." in flag_format:
            prefix, suffix = flag_format.split("...", 1)
            return (
                candidate.startswith(prefix)
                and candidate.endswith(suffix)
                and len(candidate) > len(prefix) + len(suffix)
            )
        if "{...}" in flag_format:
            prefix = flag_format.split("{...}", 1)[0]
            return candidate.startswith(prefix + "{") and candidate.endswith("}")
        return candidate == flag_format

    def _transition(
        self,
        challenge: Mapping[str, Any],
        action: str,
    ) -> dict[str, Any]:
        status = challenge["status"]
        if status == "solved":
            raise ServiceError(
                "a solved challenge is immutable",
                status=409,
                code="invalid_transition",
            )
        if action == "pause":
            if status not in {"queued", "ready", "running"}:
                raise ServiceError("challenge cannot be paused", status=409)
            next_status = "paused"
        elif action == "resume":
            if status not in {"paused", "stopped"}:
                raise ServiceError("challenge is not paused or stopped", status=409)
            next_status = "ready"
        elif action == "stop":
            if status == "stopped":
                next_status = "stopped"
            else:
                next_status = "stopped"
        else:
            raise ServiceError("invalid transition", status=409)
        state = copy.deepcopy(challenge["state"])
        state.setdefault("completed_actions", []).append(
            {"action": action, "at": utc_now()}
        )
        if action == "resume":
            circuit = state.get("circuit") or CircuitBreaker.initial_state()
            circuit["tripped"] = False
            circuit["trip_reason"] = None
            circuit["no_progress_count"] = 0
            state["circuit"] = circuit
        updated = self.db.update_challenge(
            challenge["id"], {"status": next_status, "state": state}
        )
        self.db.audit(
            "challenge_" + action,
            {"from": status, "to": next_status},
            challenge_id=challenge["id"],
        )
        return self._decorate_challenge(updated)

    def list_scopes(self) -> list[dict[str, Any]]:
        return self.db.list_scopes()

    def add_scope(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ServiceError("request body must be an object")
        raw = payload.get("pattern")
        if not isinstance(raw, str):
            raise ServiceError("scope pattern is required", code="invalid_scope")
        try:
            pattern, kind = validate_scope_pattern(raw)
        except ValueError as exc:
            raise ServiceError(str(exc), code="invalid_scope") from exc
        enabled = payload.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ServiceError("enabled must be boolean", code="invalid_scope")
        with self._action_lock:
            try:
                return self.db.add_scope(pattern, kind, enabled=enabled)
            except sqlite3.IntegrityError as exc:
                raise ServiceError(
                    "scope already exists",
                    status=409,
                    code="duplicate_scope",
                ) from exc

    def delete_scope(self, scope_id: int) -> dict[str, Any]:
        with self._action_lock:
            if not self.db.delete_scope(scope_id):
                raise ServiceError("scope not found", status=404, code="scope_not_found")
        return {"ok": True, "deleted_id": scope_id}

    def list_audit(
        self,
        *,
        limit: int = 100,
        challenge_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.db.list_audit(limit=limit, challenge_id=challenge_id)

    def _preprocess_challenge(
        self,
        challenge: Mapping[str, Any],
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        artifacts = list(challenge.get("artifacts", ()))
        fingerprint = stable_hash(
            {
                "version": PREPROCESSOR_VERSION,
                "solver_version": SOLVER_VERSION,
                "artifacts": [artifact.get("sha256") for artifact in artifacts],
                "crypto_description": stable_hash(str(challenge.get("description", "")))
                if challenge.get("category") == "crypto"
                else "",
                "web_solver": WEB_SOLVER_VERSION
                if challenge.get("category") == "web"
                else "",
            }
        )
        cache_key = "preprocess:" + fingerprint
        cached = None if force_refresh else self.db.cache_get(cache_key)
        cache_hit = cached is not None
        if cached is None:
            by_id = {
                item["id"]: item
                for item in self.db.get_artifact_contents(str(challenge["id"]))
            }
            analyzed: list[dict[str, Any]] = []
            crypto_sources: list[dict[str, str]] = [
                {
                    "name": "challenge_description",
                    "sha256": stable_hash(str(challenge.get("description", ""))),
                    "text": str(challenge.get("description", "")),
                }
            ]
            web_sources: list[dict[str, str]] = [
                {
                    "name": "challenge_description",
                    "sha256": stable_hash(str(challenge.get("description", ""))),
                    "text": str(challenge.get("description", "")),
                }
            ]
            for artifact in artifacts:
                stored = by_id.get(artifact.get("id"))
                if stored is None:
                    continue
                analyzed.append(
                    preprocess_artifact(
                        stored["name"], stored["content"], metadata=stored
                    )
                )
                if stored.get("kind") == "text" and len(stored["content"]) <= MAX_TEXT_ARTIFACT_SCAN:
                    decoded_text = stored["content"].decode("utf-8", errors="replace")
                    crypto_sources.append(
                        {
                            "name": stored["name"],
                            "sha256": stored["sha256"],
                            "text": decoded_text,
                        }
                    )
                    web_sources.append(
                        {
                            "name": stored["name"],
                            "sha256": stored["sha256"],
                            "text": decoded_text,
                        }
                    )
            solver = (
                solve_crypto_sources(
                    crypto_sources, flag_format=str(challenge["flag_format"])
                )
                if challenge.get("category") == "crypto"
                else {"version": SOLVER_VERSION, "facts": [], "candidates": [], "routes": []}
            )
            web_solver = (
                solve_web_sources(web_sources, flag_format=str(challenge["flag_format"]))
                if challenge.get("category") == "web"
                else {"version": WEB_SOLVER_VERSION, "facts": [], "signals": [], "routes": [], "parameters": [], "candidates": []}
            )
            cached = {
                "fingerprint": fingerprint,
                "artifacts": analyzed,
                "solver": solver,
                "web_solver": web_solver,
            }
            self.db.cache_set(cache_key, cached)

        facts: list[str] = []
        safety_notes: list[str] = []
        candidates: list[dict[str, Any]] = []
        for artifact in cached.get("artifacts", []):
            if not isinstance(artifact, Mapping):
                continue
            name = self._bounded_text(artifact.get("artifact_name"), 160) or "artifact"
            for fact in artifact.get("facts", []):
                bounded = self._bounded_text(fact, 500)
                if bounded:
                    facts.append(f"[{name}] {bounded}")
            for note in artifact.get("safety_notes", []):
                bounded = self._bounded_text(note, 300)
                if bounded:
                    safety_notes.append(f"[{name}] {bounded}")
            for candidate in artifact.get("candidates", []):
                if not isinstance(candidate, Mapping):
                    continue
                value = candidate.get("value")
                if isinstance(value, str) and self._flag_matches(value, challenge["flag_format"]):
                    candidates.append(dict(candidate))
        solver = cached.get("solver", {})
        if isinstance(solver, Mapping):
            for fact in solver.get("facts", []):
                bounded = self._bounded_text(fact, 500)
                if bounded:
                    facts.append("[deterministic crypto] " + bounded)
            for candidate in solver.get("candidates", []):
                if not isinstance(candidate, Mapping):
                    continue
                value = candidate.get("value")
                if isinstance(value, str) and self._flag_matches(value, challenge["flag_format"]):
                    candidates.append(dict(candidate))
        web_solver = cached.get("web_solver", {})
        web_facts: list[str] = []
        web_routes: list[dict[str, Any]] = []
        web_signals: list[dict[str, Any]] = []
        if isinstance(web_solver, Mapping):
            for fact in web_solver.get("facts", []):
                bounded = self._bounded_text(fact, 500)
                if bounded:
                    web_facts.append(bounded)
                    facts.append("[deterministic web] " + bounded)
            for signal in web_solver.get("signals", []):
                if isinstance(signal, Mapping):
                    web_signals.append(dict(signal))
            for route in web_solver.get("routes", []):
                if isinstance(route, Mapping):
                    web_routes.append(dict(route))
            for candidate in web_solver.get("candidates", []):
                if not isinstance(candidate, Mapping):
                    continue
                value = candidate.get("value")
                if isinstance(value, str) and self._flag_matches(value, challenge["flag_format"]):
                    candidates.append(dict(candidate))
        unique_candidates = {
            (item.get("value"), item.get("evidence_id")): item for item in candidates
        }
        return {
            "fingerprint": fingerprint,
            "cache_hit": cache_hit,
            "artifacts": cached.get("artifacts", []),
            "facts": list(dict.fromkeys(facts))[:MAX_PREPROCESS_FACTS],
            "safety_notes": list(dict.fromkeys(safety_notes))[:16],
            "candidates": list(unique_candidates.values()),
            "solver_routes": [
                self._bounded_text(route.get("route"), 80)
                for route in solver.get("routes", [])
                if isinstance(route, Mapping) and self._bounded_text(route.get("route"), 80)
            ][:12]
            if isinstance(solver, Mapping)
            else [],
            "web_facts": web_facts[:24],
            "web_routes": web_routes[:96],
            "web_signals": web_signals[:24],
            "web_parameters": [
                self._bounded_text(item, 80)
                for item in web_solver.get("parameters", [])
                if self._bounded_text(item, 80)
            ][:128]
            if isinstance(web_solver, Mapping)
            else [],
        }

    @staticmethod
    def _unique_deterministic_candidate(state: Mapping[str, Any]) -> dict[str, Any] | None:
        candidates = state.get("deterministic_candidates", [])
        if not isinstance(candidates, list):
            return None
        values = {
            item.get("value")
            for item in candidates
            if isinstance(item, Mapping) and isinstance(item.get("value"), str)
        }
        if len(values) != 1:
            return None
        return next(
            (dict(item) for item in candidates if isinstance(item, Mapping)),
            None,
        )

    def _decorate_challenge(
        self,
        challenge: Mapping[str, Any],
        *,
        scope_guard: ScopeGuard | None = None,
    ) -> dict[str, Any]:
        result = copy.deepcopy(dict(challenge))
        target = result.get("target", "")
        result["scope_authorized"] = (
            (scope_guard or ScopeGuard(self.db.list_scopes())).is_allowed(target)
            if target
            else None
        )
        result["untrusted_data"] = True
        result["security"] = {
            "hostile_prompt": result.get("burn_score", 0) >= 0.60,
            "large_model_escalation_blocked": result.get("burn_score", 0) >= 0.60,
            "raw_artifacts_sent_to_models": False,
        }
        return result

    @staticmethod
    def _bounded_text(value: Any, limit: int) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            value = str(value)
        return value.strip()[:limit]

    @staticmethod
    def _confidence(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return 0.5
        return round(max(0.0, min(float(value), 1.0)), 2)
