# CyLab CTF Primer: distilled operating guide

Source: [The CTF Primer](https://primer.cylabacademy.org/). This is a compact
operational summary, not a copy of the book. Use it for authorized CTF labs and
local artifacts only; the Primer's vulnerable demonstrations are not a blanket
allowlist for network requests.

## Curriculum to solver behavior

| Primer area | Reusable signal | CTF Agent action |
| --- | --- | --- |
| Shell and command line | A challenge gives a file, directory, or stream and hints at `file`, `grep`, `find`, `cat`, or pipes. | Preserve/hash first; identify type; run bounded metadata, string search, filename search, and line-oriented extraction. Never execute an untrusted file by default. |
| Forensics | Long text, nested archives, disk images, or packet captures. | Route to `ctf-forensics`; preflight archives before extraction, cap bytes/members, and record file/frame/offset evidence. |
| Python | Repeated parsing, byte conversion, small transformations, or a challenge script. | Prefer a short deterministic script with explicit input/output types, exception handling, operation caps, and a clean replay. |
| Web: HTML/JavaScript/server code | Routes, forms, query/body parameters, client-side checks, cookies, templates, or server errors. | Build a route → input → trust-boundary → sink map from captured material. Treat client-side checks as hints, not authorization. Use XSS/SQLi reasoning only in a separately allowlisted lab; never exfiltrate cookies or data. |
| Cryptography | Encodings, substitution/transposition/key ciphers, RSA/AES/hash terminology, or repeated numerical relations. | Normalize exact bytes and parameters; select an evidence-gated bounded route; re-encrypt/recompute before verification. Do not brute-force unspecified keys. |
| Network | A supplied transcript/PCAP or an explicitly allowlisted service. | Default to offline packet parsing. Network access remains disabled until the operator adds an exact scope and approves a bounded action. |
| C, assembly, and binary exploitation | Pointers, stack frames, registers, mitigations, or a supplied ELF. | Inspect architecture/mitigations and trace the decisive branch locally. Use disposable sandboxing; do not turn a lesson into a live exploit. |
| Virtual environment and ethics | Shells, VPNs, accounts, or remote labs. | Keep credentials/secrets out of artifacts and logs; require explicit target scope; pause on ambiguous ownership or unsafe mutation. |

## Fast local workflow

1. Identify the challenge, category, expected flag format, and immutable artifact
   paths. Record provenance and hashes.
2. Start with the cheapest deterministic observation: `file`, bounded metadata,
   `strings`/grep-like search, archive listing, HTML route parsing, or exact
   parameter extraction. Do not send raw binary/base64/log blobs to a model.
3. State one hypothesis with its prerequisite, expected information gain, and a
   stop condition. Run only the smallest check that can falsify it.
4. Record new facts, failed actions, evidence locators, and token/tool cost. A
   repeated request or non-progressing path trips a circuit breaker.
5. Reproduce a candidate from clean inputs and require the independent verifier.
   A flag-shaped string or a caller's `reproduced=true` claim is not proof.
6. Distill only the general method (`signal → prerequisite → bounded check →
   stop → verification`) into a category reference; keep challenge-specific
   values in the challenge workspace.

## Primer-derived safety boundaries

- The Primer demonstrates vulnerable web behavior for learning. The Agent may
  model the same concepts against synthetic/local fixtures, but must not submit
  cookie-stealing, destructive, or data-exfiltration payloads to the Primer site.
- A webshell or VPN is an execution environment, not authorization. Add an exact
  hostname/IP/port to the scope list before any network action.
- Keep remote service examples such as `nc`, `wget`, or HTTP requests disabled in
  default CI. Convert them into a captured transcript or local fixture for tests.
- For binaries, use non-root disposable execution with resource limits and no
  secrets mount. Prefer static inspection before running code.
