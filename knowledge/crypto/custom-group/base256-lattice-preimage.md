# Base-256 lowercase preimage in a custom group hash

When a challenge hashes `m` as `g^int.from_bytes(prefix + m, big) mod p`,
four consecutive one-byte messages expose the unknown prime:

`gcd(h(a)h(c)-h(b)^2, h(b)h(d)-h(c)^2)` is a small multiple of `p`.

For the target padded integer `v` and a lowercase preimage of length `l`,
center each byte at 109: `x_i = byte_i - 109`, so `x_i ∈ [-12,13]`. Solve

`sum(256^i*x_i) + s + k*(p-1) = 0`

with an LLL lattice whose first column is weighted (the identity columns
encode the centered bytes). Increase `l` from about 100 until a reduced row
`[0,1,x_(l-1),...,x_0]` is found, then verify the collision by direct modular
exponentiation. This is a reusable lattice route, not a brute-force hash
search; keep an LLL backend available for live instances. Since the lattice
already contains a `(p-1,0,...)` row, replace each large `256^i` entry with its
residue modulo `p-1` before reduction; this is a unimodular basis change and
usually makes a large speed difference. A fast approximate reducer can search
lengths in parallel, but an exact reducer or direct congruence replay must
reject any false row.

The author writeup for Firebird Internal CTF 2022 documents the same centered
base-256 construction and the four-query prime recovery.
