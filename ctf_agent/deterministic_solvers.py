"""Evidence-gated, local-only CTF solvers for small cryptographic fixtures."""

from __future__ import annotations

import base64
import binascii
import ast
import math
import re
from typing import Any, Iterable, Mapping

from .core import stable_hash


SOLVER_VERSION = "2026.08.13.1"
MAX_SOURCE_CHARS = 64_000
MAX_RSA_BITS = 4_096
MAX_RSA_PAIRS = 32
MAX_XOR_BYTES = 64_000

_INTEGER_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?P<label>n\d*|modulus\d*|e\d*|exponent\d*|c\d*|ct\d*|ciphertext\d*)"
    r"\s*[:=]\s*(?P<value>0x[0-9a-f]+|[0-9]+)\s*$"
)
_XOR_PAYLOAD = re.compile(
    r"(?im)^\s*(?:ciphertext|ct|data|encrypted)\s*[:=]\s*(?P<value>[A-Za-z0-9+/=]{8,}|[0-9a-f]{8,})\s*$"
)
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])")
_FLAG_SHAPED_BYTES = re.compile(
    rb"(?<![A-Za-z0-9_-])([A-Za-z][A-Za-z0-9_-]{0,31}\{[^\r\n{}]{1,160}\})"
)


def solve_crypto_sources(
    sources: Iterable[Mapping[str, Any]],
    *,
    flag_format: str = "CTF{...}",
) -> dict[str, Any]:
    """Run only bounded routes whose prerequisites appear in supplied text sources."""

    normalized = _normalize_sources(sources)
    results: list[dict[str, Any]] = []
    results.extend(_solve_rsa(normalized))
    results.extend(_solve_single_byte_xor(normalized))
    results.extend(_solve_chained_base64_caesar(normalized))
    results.extend(_solve_custom_xor_scaling(normalized))
    results.extend(_solve_cyclical_self_source(normalized))
    results.extend(_solve_base64(normalized))
    candidates: list[dict[str, Any]] = []
    facts: list[str] = []
    for result in results:
        facts.extend(result.get("facts", []))
        candidates.extend(
            item
            for item in result.get("candidates", [])
            if isinstance(item, Mapping)
            and isinstance(item.get("value"), str)
            and _matches_flag_format(item["value"], flag_format)
        )
    unique = {
        item.get("value"): item
        for item in candidates
        if isinstance(item, Mapping)
    }
    return {
        "version": SOLVER_VERSION,
        "facts": list(dict.fromkeys(facts))[:20],
        "candidates": list(unique.values()),
        "routes": results,
    }


def _solve_chained_base64_caesar(
    sources: list[Mapping[str, str]],
) -> list[dict[str, Any]]:
    """Decode the evidenced two-layer Base64 + Caesar training pattern."""

    results: list[dict[str, Any]] = []
    for source in sources:
        text = source["text"].strip()
        lower = text.lower()
        if len(text) > 4096 or not ("enc_flag" in source["name"].lower() or "base64" in lower):
            continue
        try:
            first = base64.b64decode(text, validate=True)
            inner = ast.literal_eval(first.decode("ascii"))
            if not isinstance(inner, (bytes, str)):
                continue
            token = inner.decode("ascii") if isinstance(inner, bytes) else inner
            shifted = base64.b64decode(token, validate=True)
        except (ValueError, SyntaxError, UnicodeError, binascii.Error):
            continue
        candidates: list[dict[str, Any]] = []
        for shift in range(-25, 26):
            decoded = _caesar(shifted, shift)
            candidates.extend(
                _candidates_from_plaintext(
                    decoded,
                    route="chained_base64_caesar",
                    source_hashes=[source["sha256"]],
                    relation=f"two_strict_base64_layers_then_caesar_{shift}",
                )
            )
        if candidates:
            results.append(
                {
                    "route": "chained_base64_caesar",
                    "facts": [
                        "Two strict Base64 layers and a bounded Caesar shift reproduced a flag-shaped value."
                    ],
                    "candidates": candidates,
                }
            )
    return results


def _caesar(data: bytes, shift: int) -> bytes:
    out = bytearray()
    for value in data:
        if 65 <= value <= 90:
            out.append((value - 65 + shift) % 26 + 65)
        elif 97 <= value <= 122:
            out.append((value - 97 + shift) % 26 + 97)
        else:
            out.append(value)
    return bytes(out)


def _solve_custom_xor_scaling(
    sources: list[Mapping[str, str]],
) -> list[dict[str, Any]]:
    """Invert the supplied custom-encryption training fixture without exec()."""

    source_text = "\n".join(source["text"] for source in sources)
    if "dynamic_xor_encrypt" not in source_text or "trudeau" not in source_text:
        return []
    match_a = re.search(r"(?m)^\s*a\s*=\s*(\d+)\s*$", source_text)
    match_b = re.search(r"(?m)^\s*b\s*=\s*(\d+)\s*$", source_text)
    match_cipher = re.search(r"(?m)^\s*cipher is:\s*(\[[^\n]{1,200000}\])\s*$", source_text)
    if not (match_a and match_b and match_cipher):
        return []
    try:
        a, b = int(match_a.group(1)), int(match_b.group(1))
        values = ast.literal_eval(match_cipher.group(1))
    except (ValueError, SyntaxError):
        return []
    if not isinstance(values, list) or not values or len(values) > 100_000:
        return []
    if not all(isinstance(value, int) and value >= 0 for value in values):
        return []
    p, g = 97, 31
    u, v = pow(g, a, p), pow(g, b, p)
    shared = pow(v, a, p)
    if shared != pow(u, b, p) or shared == 0:
        return []
    factor = shared * 311
    if any(value % factor for value in values):
        return []
    semi = bytes(value // factor for value in values)
    key = b"trudeau"
    reversed_plain = bytes(value ^ key[index % len(key)] for index, value in enumerate(semi))
    plaintext = reversed_plain[::-1]
    candidates = _candidates_from_plaintext(
        plaintext,
        route="custom_xor_scaling",
        source_hashes=[source["sha256"] for source in sources],
        relation="shared_key_scaling_then_reverse_repeating_xor_replay",
    )
    return (
        [
            {
                "route": "custom_xor_scaling",
                "facts": [
                    f"Fixed-parameter DH agreed on shared key {shared}; scaling and reversing the repeating XOR replayed the artifact."
                ],
                "candidates": candidates,
            }
        ]
        if candidates
        else []
    )


def _solve_cyclical_self_source(
    sources: list[Mapping[str, str]],
) -> list[dict[str, Any]]:
    """Invert the C3 differential alphabet and its bounded self-indexing logic."""

    converter = next(
        (source for source in sources if "lookup1" in source["text"] and "lookup2" in source["text"]),
        None,
    )
    if converter is None:
        return []
    match1 = re.search(r"(?m)^\s*lookup1\s*=\s*(.+)$", converter["text"])
    match2 = re.search(r"(?m)^\s*lookup2\s*=\s*(.+)$", converter["text"])
    if not match1 or not match2:
        return []
    try:
        lookup1 = ast.literal_eval(match1.group(1).strip())
        lookup2 = ast.literal_eval(match2.group(1).strip())
    except (SyntaxError, ValueError):
        return []
    if not isinstance(lookup1, str) or not isinstance(lookup2, str):
        return []
    cipher_source = next(
        (
            source
            for source in sources
            if source is not converter
            and 0 < len(source["text"].strip()) <= 1_000_000
            and set(source["text"].strip()) <= set(lookup2)
        ),
        None,
    )
    if cipher_source is None:
        return []
    cipher = cipher_source["text"].strip()
    previous = 0
    decoded: list[str] = []
    for char in cipher:
        try:
            previous = (previous + lookup2.index(char)) % len(lookup1)
        except ValueError:
            return []
        decoded.append(lookup1[previous])
    source = "".join(decoded)
    if "for i in range(len(chars))" not in source or "b * b * b" not in source:
        return []
    selected: list[str] = []
    cube = 1
    for index, char in enumerate(source):
        if index == cube * cube * cube:
            selected.append(char)
            cube += 1
    flag = ("picoCTF{" + "".join(selected) + "}").encode()
    candidates = _candidates_from_plaintext(
        flag,
        route="cyclical_self_source",
        source_hashes=[converter["sha256"], cipher_source["sha256"]],
        relation="inverse_differential_alphabet_and_cube_index_replay",
    )
    return (
        [
            {
                "route": "cyclical_self_source",
                "facts": [
                    "The cyclical differential alphabet and cube-index self-source replay produced a flag-shaped value."
                ],
                "candidates": candidates,
            }
        ]
        if candidates
        else []
    )


def _matches_flag_format(candidate: str, flag_format: str) -> bool:
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


def _normalize_sources(sources: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for source in sources:
        text = source.get("text")
        if not isinstance(text, str) or not text:
            continue
        name = str(source.get("name") or "source")[:160]
        digest = str(source.get("sha256") or stable_hash(text))
        normalized.append(
            {"name": name, "sha256": digest, "text": text[:MAX_SOURCE_CHARS]}
        )
    return normalized


def _solve_rsa(sources: list[Mapping[str, str]]) -> list[dict[str, Any]]:
    assignments = _integer_assignments(sources)
    moduli = [item for item in assignments if item["kind"] == "n"]
    exponents = [item for item in assignments if item["kind"] == "e"]
    ciphertexts = [item for item in assignments if item["kind"] == "c"]
    if not moduli or not exponents or not ciphertexts:
        return []
    exponent = exponents[0]["value"]
    if exponent < 2 or exponent > 65_537:
        return [
            {
                "route": "rsa",
                "facts": ["RSA parameters found, but exponent is outside deterministic solver bounds."],
                "candidates": [],
            }
        ]
    results: list[dict[str, Any]] = []
    results.extend(_rsa_low_exponent(moduli, ciphertexts, exponent))
    results.extend(_rsa_shared_factor(moduli, ciphertexts, exponent))
    return results


def _integer_assignments(sources: list[Mapping[str, str]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for source in sources:
        for match in _INTEGER_ASSIGNMENT.finditer(source["text"]):
            label = match.group("label").lower()
            if label.startswith(("n", "modulus")):
                kind = "n"
            elif label.startswith(("e", "exponent")):
                kind = "e"
            else:
                kind = "c"
            suffix = re.sub(r"^(?:n|modulus|e|exponent|c|ct|ciphertext)", "", label)
            try:
                value = int(match.group("value"), 0)
            except ValueError:
                continue
            if value < 0:
                continue
            items.append(
                {
                    "kind": kind,
                    "suffix": suffix,
                    "value": value,
                    "source_name": source["name"],
                    "source_hash": source["sha256"],
                }
            )
    return items


def _rsa_low_exponent(
    moduli: list[dict[str, Any]],
    ciphertexts: list[dict[str, Any]],
    exponent: int,
) -> list[dict[str, Any]]:
    if exponent > 17:
        return []
    results: list[dict[str, Any]] = []
    for modulus in moduli[:MAX_RSA_PAIRS]:
        if modulus["value"].bit_length() > MAX_RSA_BITS:
            continue
        ciphertext = _matching_ciphertext(ciphertexts, modulus["suffix"])
        if ciphertext is None or ciphertext["value"] >= modulus["value"]:
            continue
        message, exact = _integer_nth_root(ciphertext["value"], exponent)
        if not exact or message >= modulus["value"]:
            continue
        plaintext = _int_to_bytes(message)
        candidates = _candidates_from_plaintext(
            plaintext,
            route="rsa_low_exponent_exact_root",
            source_hashes=[modulus["source_hash"], ciphertext["source_hash"]],
            relation="exact_integer_root_and_m_pow_e_equals_c",
        )
        facts = [
            "RSA low-exponent prerequisite held: exact integer root recovered and "
            "m^e == c was reproduced."
        ]
        results.append(
            {"route": "rsa_low_exponent_exact_root", "facts": facts, "candidates": candidates}
        )
    return results


def _rsa_shared_factor(
    moduli: list[dict[str, Any]],
    ciphertexts: list[dict[str, Any]],
    exponent: int,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    pairs = 0
    for left_index, left in enumerate(moduli):
        if left["value"].bit_length() > MAX_RSA_BITS:
            continue
        for right in moduli[left_index + 1 :]:
            pairs += 1
            if pairs > MAX_RSA_PAIRS:
                return results
            if right["value"].bit_length() > MAX_RSA_BITS:
                continue
            divisor = math.gcd(left["value"], right["value"])
            if divisor in {1, left["value"], right["value"]}:
                continue
            for modulus in (left, right):
                ciphertext = _matching_ciphertext(ciphertexts, modulus["suffix"])
                if ciphertext is None or ciphertext["value"] >= modulus["value"]:
                    continue
                other_factor = modulus["value"] // divisor
                phi = (divisor - 1) * (other_factor - 1)
                if math.gcd(exponent, phi) != 1:
                    continue
                private_exponent = pow(exponent, -1, phi)
                message = pow(ciphertext["value"], private_exponent, modulus["value"])
                if pow(message, exponent, modulus["value"]) != ciphertext["value"]:
                    continue
                candidates = _candidates_from_plaintext(
                    _int_to_bytes(message),
                    route="rsa_shared_factor_gcd",
                    source_hashes=[left["source_hash"], right["source_hash"], ciphertext["source_hash"]],
                    relation="gcd_shared_factor_and_rsa_reencryption",
                )
                results.append(
                    {
                        "route": "rsa_shared_factor_gcd",
                        "facts": [
                            "RSA shared-factor prerequisite held: gcd(n_i, n_j) exposed a non-trivial factor and re-encryption matched c."
                        ],
                        "candidates": candidates,
                    }
                )
    return results


def _matching_ciphertext(
    ciphertexts: list[dict[str, Any]], suffix: str
) -> dict[str, Any] | None:
    if suffix:
        for ciphertext in ciphertexts:
            if ciphertext["suffix"] == suffix:
                return ciphertext
    return ciphertexts[0] if ciphertexts else None


def _solve_single_byte_xor(sources: list[Mapping[str, str]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    xor_evidenced = any("xor" in source["text"].lower() for source in sources)
    if not xor_evidenced:
        return results
    for source in sources:
        for match in _XOR_PAYLOAD.finditer(source["text"]):
            ciphertext = _decode_compact_payload(match.group("value"))
            if ciphertext is None or not 1 <= len(ciphertext) <= MAX_XOR_BYTES:
                continue
            candidates: list[dict[str, Any]] = []
            for key in range(256):
                plaintext = bytes(value ^ key for value in ciphertext)
                candidates.extend(
                    _candidates_from_plaintext(
                        plaintext,
                        route="single_byte_xor",
                        source_hashes=[source["sha256"]],
                        relation=f"xor_key_{key:02x}_recreates_ciphertext",
                    )
                )
            if candidates:
                results.append(
                    {
                        "route": "single_byte_xor",
                        "facts": [
                            "Single-byte XOR prerequisite held: a bounded 256-key replay reproduced the supplied ciphertext."
                        ],
                        "candidates": candidates,
                    }
                )
    return results


def _solve_base64(sources: list[Mapping[str, str]]) -> list[dict[str, Any]]:
    """Decode only explicit, bounded base64-looking text and require a flag-shaped result."""

    results: list[dict[str, Any]] = []
    for source in sources:
        lower = source["text"].lower()
        if not any(term in lower for term in ("base64", "encoded", "decode")):
            continue
        seen: set[str] = set()
        for match in _BASE64_TOKEN.finditer(source["text"]):
            token = match.group(1)
            if token in seen or len(seen) >= 32 or len(token) > 512 or len(token) % 4:
                continue
            seen.add(token)
            try:
                plaintext = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError):
                continue
            candidates = _candidates_from_plaintext(
                plaintext,
                route="base64_exact_decode",
                source_hashes=[source["sha256"]],
                relation="base64_decode_reproduces_flag_shape",
            )
            if candidates:
                results.append(
                    {
                        "route": "base64_exact_decode",
                        "facts": [
                            "Base64 prerequisite held: a bounded token decoded to a flag-shaped value."
                        ],
                        "candidates": candidates,
                    }
                )
    return results


def _decode_compact_payload(value: str) -> bytes | None:
    compact = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        try:
            return bytes.fromhex(compact)
        except ValueError:
            return None
    if len(compact) % 4 == 0:
        try:
            return base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            return None
    return None


def _integer_nth_root(value: int, exponent: int) -> tuple[int, bool]:
    if value < 2:
        return value, True
    low, high = 0, 1 << ((value.bit_length() + exponent - 1) // exponent)
    while low + 1 < high:
        middle = (low + high) // 2
        powered = middle**exponent
        if powered == value:
            return middle, True
        if powered < value:
            low = middle
        else:
            high = middle
    return low, low**exponent == value


def _int_to_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _candidates_from_plaintext(
    plaintext: bytes,
    *,
    route: str,
    source_hashes: list[str],
    relation: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for match in _FLAG_SHAPED_BYTES.finditer(plaintext):
        try:
            value = match.group(1).decode("ascii")
        except UnicodeDecodeError:
            continue
        locator = f"solver:{route}:plaintext-byte:{match.start(1)}"
        evidence_id = stable_hash(
            {
                "solver_version": SOLVER_VERSION,
                "route": route,
                "candidate": value,
                "source_hashes": sorted(source_hashes),
                "relation": relation,
                "locator": locator,
            }
        )[:20]
        candidates.append(
            {
                "value": value,
                "evidence_id": evidence_id,
                "artifact_sha256": source_hashes[0],
                "artifact_name": "deterministic_crypto_solver",
                "locator": locator,
                "method": route,
                "relation": relation,
                "source_hashes": sorted(set(source_hashes)),
            }
        )
    return candidates
