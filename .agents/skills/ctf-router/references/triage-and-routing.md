# Triage and routing

## Deterministic first pass

Collect only bounded evidence:

1. Artifact name, size, SHA-256, media type, magic bytes, architecture, and container
   members without extraction.
2. A small strings/header sample and obvious metadata.
3. Challenge-supplied category as a hint, never as ground truth.
4. Prompt-injection signals, repeated filler, oversized encoded regions, and requests
   to force a model/tool/secret action.

## Category signals and coverage

| Signal | Route | Coverage / boundary |
| --- | --- | --- |
| HTTP source, routes, cookies, JWT, templates | `ctf-web` | Supported; remote requests still require an explicit allowlist. |
| ELF + service/protocol + memory-corruption hints | `ctf-pwn` | Supported; use only supplied artifacts or allowlisted challenge service. |
| Executable, APK, bytecode, license/check routine | `ctf-reverse` | Supported for static or isolated analysis of supplied programs. |
| Nonce, modulus, ciphertext, algebraic parameters | `ctf-crypto` | Supported for supplied scheme/material; bounded attacks only. |
| SSH prompt, Unix filesystem, permissions, local service, shell, cron, setuid, or Git repository | `ctf-bandit` | Supported for authorized Bandit-style practice; bounded local/service checks only. |
| PCAP, disk/memory image, logs, archive, ordinary metadata | `ctf-forensics` | Supported preservation and bounded extraction. |
| Image/audio hidden-data clue | bounded offline triage, then `ctf-forensics` only for the artifact-extraction facet | No standalone stego solver. Pause if the remaining problem is steganalysis without a bounded forensics task. |
| Public-source identity/location clue | pause, unless all needed sources are supplied offline | No OSINT skill. Never discover or enumerate public sources, accounts, or people. |
| HDL, firmware, UART/JTAG/logic trace | `ctf-reverse` only for supplied firmware/static code; otherwise pause | No hardware skill. Do not operate physical interfaces or probe devices. |
| Mobile APK/bytecode/native library | `ctf-reverse` for supplied static artifacts | No mobile skill. Pause device, emulator, cloud-account, or live-app work lacking an explicit safe capability. |
| Contract source, transaction fixture, signature/math data | `ctf-crypto` only for a bounded supplied crypto/protocol facet | No blockchain skill. Pause chain RPC, explorer, wallet, or network-dependent work. |
| Puzzles or mixed artifacts with no narrow signal | bounded offline classification, then pause | No misc solver. Do not dispatch a generic agent or escalate merely because it is `misc`. |

Report alternatives with confidence instead of spawning every specialist. Record one
of `supported`, `bridged`, or `paused_unsupported` for the selected route. A bridge
must name its exact supported facet and its stop condition; it is not a category
substitution. For `paused_unsupported`, preserve the evidence and state the missing
capability or authority needed to continue.

## Cost-aware routing

- Metadata, hashing, classification, extraction, and flag-format checks: deterministic.
- Short normalization, summarization, or clear repeated task: Luna.
- Cross-artifact reasoning or category solving: Terra.
- One unresolved, demonstrably hard hypothesis after cheaper failure: Sol Ultra.

Do not escalate when AI-burn score is hostile, the request repeats unchanged work, a
tool can answer directly, or reserve would be consumed.

The `ctf-bandit` skill covers Unix/Linux CTF fundamentals from Bandit levels 0–33:
SSH, safe file discovery, encoding/compression, localhost/TLS, cron, setuid,
restricted shells, and Git history. It stores only general techniques, never
passwords, flags, or instance transcripts.
