# Solver state contract

Maintain a compact state rather than replaying the full conversation:

```json
{
  "challenge_id": "event-id",
  "objective": "one sentence",
  "category": "web",
  "category_confidence": 0.82,
  "routing": {
    "status": "supported",
    "skill": "ctf-web",
    "supported_facet": null,
    "pause_reason": null
  },
  "scope": {"network_enabled": false, "targets": []},
  "artifacts": [{"path": "...", "sha256": "...", "kind": "..."}],
  "known_facts": [],
  "observations": [],
  "hypotheses": [],
  "discarded_hypotheses": [],
  "completed_actions": [],
  "failed_actions": [],
  "next_candidate_actions": [],
  "burn_score": 0.0,
  "injection_signals": [],
  "token_spent": 0,
  "model_calls": {"luna": 0, "terra": 0, "sol": 0},
  "verification": {"status": "not_started", "reason": null}
}
```

Rules:

- Store claims in `known_facts` only with an artifact, command, or reproducible result.
- Fingerprint failed actions so an unchanged attempt is not repeated.
- Keep raw output in bounded artifact files; state contains a short finding and path.
- Retrieve only facts relevant to the pending action.
- Set `routing.status` to `supported`, `bridged`, or `paused_unsupported`. A
  `bridged` route must identify the exact facet a listed skill can handle; a paused
  route must not consume model budget for unguided category solving.
- Valid lifecycle states are `queued`, `ready`, `running`, `paused`, `stopped`,
  `solved`, and `rejected`.
- `solved` requires an independently verified candidate. `rejected` records why the
  candidate failed; it is not proof that the whole challenge is unsolvable.
