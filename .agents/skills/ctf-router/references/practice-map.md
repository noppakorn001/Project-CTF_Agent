# CTF practice map and knowledge-distillation workflow

Use this reference only when the operator asks to research practice challenges or
update the skill library. It is a curriculum index, not permission to access a
platform account, download arbitrary targets, or reuse a flag. Prefer intentionally
vulnerable training labs and supplied challenge artifacts; keep live target access
separately allowlisted.

## Category-to-practice map

For the Primer curriculum and picoCTF-specific examples, read
[cylab-primer.md](cylab-primer.md) and [picoctf-practice.md](picoctf-practice.md).

| Category | Practice source / challenge families | Reusable method to extract |
| --- | --- | --- |
| General / mixed | [picoCTF learning resources](https://picoctf.org/resources.html) and picoGym | Record the artifact signal, required primitive, cheapest deterministic check, and verification relation. |
| Web | [PortSwigger Web Security Academy topics](https://portswigger.net/web-security/all-topics) and [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/) | Map route → input → trust boundary → sink; test one harmless dimension; preserve response evidence and state-change limits. Advanced parser/cache/prototype routes stay local-lab only. |
| Cryptography | [CryptoHack challenges](https://cryptohack.org/challenges/) and [CryptoHack courses](https://cryptohack.org/courses/) | Normalize bytes/integers; identify a demonstrated invariant or implementation defect; solve with bounded exact arithmetic; re-encrypt or re-check all samples. DH, ZKP, isogeny, and lattice paths require explicit parameters and caps. |
| Pwn / binary exploitation | [pwn.college binary exploitation](https://pwn.college/pwndamentals~cfe9c1cb/binary-exploitation/) | Establish architecture and mitigations, reproduce one primitive locally, then prove the smallest control/leak/write effect under the supplied runtime. Kernel/seccomp paths require a disposable VM. |
| Reverse engineering | [pwn.college reversing](https://pwn.college/reversing-hell/) and supplied ELF/DEX/JAR/Wasm artifacts | Trace input to the decisive comparison, translate only the relevant routine, and verify the candidate against the original artifact. Custom VM and obfuscation routes remain bounded/static-first. |
| Forensics / PCAP | [picoCTF forensics resources](https://picoctf.org/resources.html), [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/), and [Volatility 3 docs](https://volatility3.readthedocs.io/en/latest/) | Preserve/hash first; inventory metadata; filter a small evidence window; cite frame/offset/record and reproduce the extraction. Browser/timeline sources remain read-only. |
| Stego / media | Supplied image/audio/document artifacts, using the media facet of `ctf-forensics` | Check type, dimensions, metadata, channels, EOF/trailing bytes, and bounded transforms only when structure supports them; do not blind-brute-force. |
| Mobile / APK | Supplied APKs and [OWASP MASTG Android testing](https://mas.owasp.org/MASTG/0x05b-Android-Security-Testing/) | Route static APK/DEX/JNI analysis to `ctf-reverse`; pause device, emulator, account, or live-app work unless separately scoped. |
| Hardware / firmware | Supplied firmware, HDL, UART/JTAG traces, or logic captures | Route static firmware/container analysis to `ctf-reverse` or artifact extraction to `ctf-forensics`; pause physical probing and device mutation. |
| OSINT | Operator-supplied offline pages, documents, or identities | Preserve provenance and timestamps; pause public-source discovery, account enumeration, or personal-data research without an explicit source allowlist. |
| Blockchain | Supplied contract source, transaction fixtures, signatures, or local chain snapshot | Route bounded cryptographic/protocol reasoning to `ctf-crypto`; pause chain RPC, explorer, wallet, and network actions without explicit scope. |

## Distill one practice challenge

1. Record source, challenge identifier/title, category, artifact or explicitly
   allowlisted target, and the expected flag format. Do not record account cookies,
   secrets, or the flag itself in a shared reference.
2. Solve in a clean workspace with deterministic inspection first. Capture only the
   smallest source fragment, request, input, or output that proves the technique.
3. Write the reusable lesson as `signal → prerequisite → bounded check → stop
   condition → independent verification`. Name the exact facet; do not generalize a
   challenge-specific trick into a new skill.
4. Forward-test the lesson against a synthetic or separate training artifact without
   revealing the expected answer. Keep the test read-only and time-bounded.
5. Update the matching category playbook, its source links, and a regression check;
   leave unsupported categories as `bridged` or `paused_unsupported` in router state.

## Minimum research record

```text
source_url: <official training source>
challenge: <id/title, no flag>
category/facet: <route>
signal: <what justified the route>
cheap_check: <bounded deterministic action>
stop_condition: <when to pause>
verification: <reproduction relation>
reference_updated: <skill/reference path>
```
