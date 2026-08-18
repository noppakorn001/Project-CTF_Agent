# ECDSA nonces from an affine recurrence

## Signal

The challenge source signs many known messages with consecutive values from an
unknown LCG, `k[i+1] = a*k[i] + b (mod p)`, while ECDSA uses the curve order
`q`.  The signature pairs and exact hash-to-integer rule are available.

## Deterministic route

For adjacent signatures, eliminate each nonce:

`k[i+1] - k[i] = u[i] d + v[i] (mod q)`

where `u[i]` and `v[i]` come from the two `(r,s,z)` triples.  Build the
challenge's bounded modular lattice from consecutive `u,v` pairs.  Prefer an
exact integer LLL implementation (GMP/fplll/Sage) over high-precision Python
floating point.  Short rows with zero relation coordinates are coefficient
vectors for modular nonce relations.

## Caps and checks

- Keep the basis dimension and scaling from the source/writeup; do not enlarge
  a guessed lattice.
- Try a bounded subset of short relations (seven rows for this fixture), not an
  unbounded combination search.
- Recover the one-dimensional rational kernel and test both signs against every
  original adjacent equation.
- Derive each nonce from `k=(z+r*d)/s mod q` and replay the complete curve
  signature relation (`x(kG) == r`) before decrypting.
- For PyCryptodome AES-CTR with an eight-byte nonce and initial counter zero,
  OpenSSL uses `IV = nonce || 0^8`; hash `str(d).encode()` exactly as source.

## Reusable files

- `ctf_challenges/cryptohack_archive/solvers/2024_eclcg_solve.py`: bounded
  recovery with optional GMP backend and saved-reduction replay.
- `2024_eclcg_verify.py`: independent secp256k1 and AES-CTR verification.
