# Reused-nonce GCM tag-only oracle

## Signal

The source reuses a 96-bit GCM nonce, exposes tags for unknown associated data
and plaintext, and has operations that replace or append exactly 12 bytes.  The
target is the empty-message tag `S = E_K(J0)`.

## Deterministic route

For 12-byte values, a replacement changes only one GHASH block:

- plaintext/ciphertext difference: `ΔT = ΔC · H²`;
- associated-data difference: `ΔT = ΔA · H³`.

Because the changed value is 12 bytes, the upper 32 coefficients of the
corresponding quotient are zero.  Collect five replacement samples and solve
the resulting 32-by-128 GF(2) rows for `H^-2` and `H^-3`; match the two roots
before proceeding.

After reset, six append operations have a useful `36 -> 48` transition.  At
that boundary, subtract the length-block delta and divide by the correct power
of `H` and `x^32`; the zero high coefficients classify three consecutive
updates on one side.  Build a binary linear system for the GHASH data blocks and
`S`, brute-force only the remaining bounded side bits, and prefer the candidate
with the smallest affine kernel.  A zero-dimensional kernel is required for a
deterministic final tag; otherwise retry the instance within a finite cap.

## Reusable files

- `ctf_challenges/cryptohack_archive/solvers/2024_gcm_solve.py`
- `ctf_challenges/cryptohack_archive/solvers/pow_md5.c`

The solver uses standard-library GF(2^128) arithmetic and a self-contained PoW
accelerator; no Python crypto package or `libcrypto` link is required.
