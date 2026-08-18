# Crypto challenge playbook

Use a route only when its prerequisite is evidenced in supplied files, transcripts,
or allowlisted local service behavior. Record the exact byte-to-integer conversion
and every sample used. A valid recovery must satisfy every applicable original
relation, not merely look flag-shaped.

## Universal gate

- Decode locally and round-trip hex/base64/text encodings. Record byte lengths,
  signedness, endianness, padding, hashes, public parameters, and randomness scope.
- Make an input/output table before manipulating values. Distinguish a scheme's
  claimed design from the code path actually reached.
- Set numeric caps before searching: candidate count, operations, memory, and time.
  Do not enlarge a cap merely because the first pass failed. Stop after two failed
  tests of the same prerequisite or three non-informative iterations.
- Use Python integer arithmetic for small exact checks; use Sage only for a stated
  finite-field, polynomial, lattice, or factorization calculation with a bounded
  input set. Save version and parameters with the result.

## Evidence-gated routes

| Route | Evidence and cheap check | Stop condition | Verify |
| --- | --- | --- | --- |
| Base64 / text encoding | The supplied code or notes explicitly identify an encoding, and a bounded token decodes with strict padding into the configured flag format. | No encoding evidence, malformed padding, or decoded output is not flag-shaped. Never treat every alphanumeric string as a password. | Strict-decode the original token again, compare exact bytes, and retain the source hash and byte locator. |
| XOR / stream / CTR / OFB | Two ciphertexts demonstrably use the same keystream position (same key plus nonce/counter state), or a known plaintext aligns. Check `C1 xor C2 == P1 xor P2` over the exact overlap. | No reuse/alignment evidence, or cribs yield multiple incompatible results. Do not search arbitrary keys. | Recreate every supplied ciphertext with the recovered keystream/key material. |
| Block modes | Establish block size, mode, IV/nonce handling, and padding from code or repeated blocks. Check only mode-specific consequences: equal ECB blocks, CBC first-block relation with reused IV, or documented counter reuse. | A modern authenticated mode has unique nonce/IV evidence and no implementation defect. Never treat decryption errors as an oracle unless the supplied challenge explicitly exposes a bounded local oracle. | Re-encrypt or decrypt all samples and validate padding/tag exactly. |
| RSA | Parse `n`, `e`, ciphertext/message representatives, and padding. Compute pairwise `gcd(n_i, n_j)` across supplied moduli; test exact integer roots only when `m^e < n` is evidenced; check key equations and encoding length. | No factor/relation/size prerequisite, or OAEP/PKCS#1 encoding is correctly present without an evidenced implementation flaw. No remote chosen-ciphertext probing. | Factor/product and key equations; reapply RSA primitive and exact encoding to each sample. |
| ECDSA / DSA / ECC | Confirm curve/order, hash-to-integer rule, signature pairs, and public key. Test repeated `r` only among supplied signatures; solve the resulting linear relation only if inverses exist. Check point/order constraints before custom curve arithmetic. | No repeated or otherwise documented nonce defect, invalid point, or small bounded parameter space. | Recompute signature/public-key relation using the stated curve and message hash. |
| Hash / MAC | Identify construction and exact bytes. Test length extension only for an evidenced secret-prefix Merkle--Damg\u00e5rd construction and a finite, justified key-length range; distinguish HMAC from a raw hash. | HMAC, suffix/keyed construction, unknown framing, or an unjustified key-length range. | Recompute the supplied digest/MAC and any challenge acceptance relation from exact bytes. |
| Custom algebra | Derive equations from code; test dimensions, rank, gcd/invertibility, repeated state, and field/ring assumptions before solving. | Equations do not match all samples or the proposed space exceeds the pre-set cap. | Substitute the recovered values into every original equation and regenerate samples. |
| Diffie-Hellman or finite-group exchange | Parse the exact group, generator, public values, and subgroup order. Check order factorization, repeated/biased exponents, small-subgroup confinement, and whether a public value is outside the stated subgroup. | No parameter defect, no repeated secret, or an order/factorization calculation beyond the fixed cap. Do not query a remote oracle or alter a live exchange. | Recompute both public values/shared secret and the challenge's KDF or MAC from the recovered relation. |
| Lattice, partial leakage, or noisy modular equations | Require explicit bounds, bit leaks, related samples, or a noise model. First estimate dimension, modulus, leakage, and basis size; use Sage only for a finite, bounded lattice instance. | No stated bound/noise relation, dimension or memory cap exceeded, or a basis produces an unvalidated vector. Do not turn a vague "small secret" into brute force. | Substitute the candidate into every original equation and independently rerun the bounded reduction with recorded parameters. |
| Zero-knowledge proof or transcript protocol | Parse commitments, challenge derivation, responses, transcript binding, and verification equations. Check challenge reuse, nonce reuse, missing domain separation, and Fiat-Shamir input coverage locally. | Soundness equations hold with fresh challenges and no bounded defect; never forge a proof for an external verifier. | Run the supplied verifier on a clean transcript and check every equation plus transcript hash/domain separator. |
| Isogeny or advanced elliptic-curve fixture | Confirm field size, curve/order, basis points, and supplied map/encoding before using Sage. Keep point arithmetic and isogeny degree within a declared cap. | Parameters are malformed, map is not evidenced, or the computation exceeds the cap. Do not use public services or wallet/chain endpoints. | Recompute point/map relations and serialize the exact recovered value using the challenge's encoding. |
| PRNG or nonce/state recovery | Identify the generator, seed/state width, output truncation, and sample spacing from supplied code/transcripts. Test a bounded state reconstruction or prediction relation only when the state space and observations fit the cap. | Unknown generator, insufficient samples, or state search beyond the cap. Do not query challenge servers for extra samples. | Reproduce every supplied output and predict a withheld local sample, then regenerate any key/nonce use. |
| Authenticated stream nonce reuse | Two packets expose the same ChaCha20/Poly1305 nonce and at least one known plaintext. Check exact `P xor C` keystream reuse, then derive the bounded Poly1305 tag-difference polynomial over `2^130-5`. | Nonce equality is not evidenced, a root/carry search exceeds the declared cap, or the forged packet fails clean decrypt-and-verify on the same transcript. | Recompute the target ciphertext/tag and submit it to the challenge parser on the same connection; never reuse another instance's packet. |
| Large consecutive-point interpolation | Artifact code constructs a dense Vandermonde matrix and the first bounded lines show `x=0,1,2,...` with a declared finite field. Route to a product tree + derivative-based fast interpolation implementation. | No consecutive-point evidence, field parameters are missing, or the available runtime cannot meet the memory/time cap. Do not allocate the dense matrix. | Substitute the recovered coefficients into sampled original points and validate the downstream file/flag artifact. |
| Classical Caesar / Atbash | The challenge names or artifact text explicitly identify a monoalphabetic rotation/substitution. Enumerate 26 Caesar shifts or apply the involutive Atbash map to a bounded extracted string. | No cipher evidence, malformed output, or multiple flag-shaped candidates. | Re-run the transform against the original artifact hash and compare exact bytes. |
| CSR / certificate metadata | A supplied CSR/certificate is the only artifact and the subject/extensions are the likely carrier. Parse with OpenSSL and inspect only bounded text fields. | The flag is not in the parsed fields or the artifact is not a certificate. | Re-run parsing from the original hash and record the field locator. |
| RSA modulus omitted with `d` exposed | Source shows `ed - 1 = k(p-1)(q-1)` and the challenge gives `c,d` while hiding `n`; factor/enumerate only the evidenced 128-bit candidate space. | Factorization or candidate enumeration exceeds the declared cap, or plaintext fails exact re-encryption. | Recompute `c = m^e mod n` and independently check the recovered plaintext encoding. |
| Side-channel S-box leakage | Source returns a per-query bit count or traces correlated with `Sbox[plaintext ^ key]`; use a bounded differential/CPA model and retain query/trace counts. | No exact leakage model, service instability, or recovered key lacks clean format/replay evidence. | Replay the leakage model or CPA score on a clean sample and verify the key-derived flag format. |

## Reproducibility record

Keep a small `solve.md` or script header with artifact hashes, normalized parameters,
assumptions, cap, commands, and validation output. A candidate is only a lead until a
clean rerun and independent verifier reproduce it.

## Primary sources

- [RFC 8017, PKCS #1 v2.2](https://www.rfc-editor.org/rfc/rfc8017.html): RSA
  integer/octet conversion, primitives, and OAEP/PKCS#1 encodings.
- [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final): ECB, CBC,
  CFB, OFB, and CTR mode definitions.
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf): GCM authenticated encryption and IV uniqueness requirement.
- [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf):
  DSA/ECDSA generation and verification relations.
- [Sage modular arithmetic documentation](https://doc.sagemath.org/html/en/thematic_tutorials/group_theory.html): exact modular inverse behavior.
- [CryptoHack Diffie-Hellman challenges](https://cryptohack.org/challenges/diffie-hellman/) and [ZKP challenges](https://www.cryptohack.org/challenges/zkp/): bounded practice fixtures for protocol reasoning.
- [CryptoHack isogeny challenges](https://www.cryptohack.org/challenges/isogenies/): supplied-parameter elliptic-curve/isogeny exercises; use Sage locally and keep caps explicit.
- [CryptoHack miscellaneous challenges](https://www.cryptohack.org/challenges/misc/): includes PRNG practice; use only supplied/offline samples and do not contact its sockets from this workflow.
