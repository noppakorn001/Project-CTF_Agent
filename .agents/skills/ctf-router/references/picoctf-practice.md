# picoCTF practice map

Primary sources:

- [picoCTF getting started](https://picoctf.org/get_started.html), which
  describes picoGym as a noncompetitive practice space.
- [Official picoCTF example problems](https://github.com/picoCTF/picoCTF-2019-example-problems),
  an archived public repository containing challenge templates and examples.
- For the locally verified 2025/2026 lessons, see
  [picoctf-2025-2026.md](picoctf-2025-2026.md). It records reusable primitives
  only; challenge flags remain in their per-challenge workspaces.

Use these sources for curriculum and local fixtures, not as permission to probe
old challenge hosts. Never store account cookies, platform tokens, or shared
write-ups containing flags in the skill library.

## Challenge families and reusable methods

| Example family | Category/facet | Cheap local check | Verification relation |
| --- | --- | --- | --- |
| `grep-1` | General/file search | Identify text, search a bounded file for the configured flag format, and retain line/byte evidence. | Re-run the same search against the original artifact hash. |
| `auth1` | Crypto/encoding | Require explicit Base64 context, strict-decode a bounded token, and check the configured flag format. | Decode the original token again and compare exact bytes. |
| `client-side-java` | Web/client-side trust | Parse script/form routes and parameters; identify that JavaScript validation is client-side. | Reproduce the route map from the captured HTML; do not claim a flag when the archive contains template placeholders. |
| `store` | Native/integer arithmetic | Read source, identify signed arithmetic and state transitions, then model the smallest local input. | Reproduce the state transition in a sandbox; no remote service. |
| `pipe` | Stream processing | Parse a supplied transcript and filter flag-shaped lines; do not open a socket by default. | Replay the filter against the captured output and record the line locator. |
| `rotation` | Crypto/Caesar | Enumerate the bounded 26 Caesar shifts and retain the sole flag-shaped result. | Re-run against the original artifact hash. |
| `ReadMyCert` | Crypto/X.509 | Inspect a supplied CSR subject with OpenSSL; do not alter the request. | Re-run the subject extraction and compare the exact flag-shaped CN. |
| `HideToSee` | Crypto/steganography | For a JPEG, try empty-passphrase steghide extraction before applying the named Atbash substitution. | Require successful extraction and a clean Atbash decode; do not rely on image appearance or web write-ups alone. |
| `SRA` | Crypto/RSA | Use `ed-1 = k(p-1)(q-1)` to enumerate bounded 128-bit prime candidates and test decryption. | Reproduce the captured ciphertext/plaintext relation under the recovered modulus. |
| `PowerAnalysis` | Crypto/side-channel | Model the exact S-box leakage or use bounded CPA on supplied traces; keep query/trace caps explicit. | Replay the leakage/CPA score and independently check the recovered key format. |

## Local fixtures in this workspace

- `ctf_challenges/picoctf_auth1/` is a bounded capture derived from `auth1` and
  has an evidence-gated Base64 solver regression.
- `ctf_challenges/picoctf_client_side_java/` is a bounded HTML capture derived
  from `client-side-java`; its flag fragments remain template placeholders.

When adding another example, keep the raw artifact separate from this reference,
record its upstream path and hash, and add a regression that proves the method
without hard-coding an answer in the skill text.

## Practice record format

```text
source_url: <official picoCTF source>
challenge: <family/title, no flag>
category/facet: <route>
signal: <artifact fact that justified the route>
cheap_check: <bounded deterministic action>
stop_condition: <when to pause>
verification: <clean replay relation>
fixture: <workspace path, if local>
```
