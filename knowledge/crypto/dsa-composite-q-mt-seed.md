# DSA composite-q and seeded primality checks

When a challenge lets the client choose DSA parameters, inspect the library's
parameter validation and every source of randomness.  If a seed controls
`os.urandom`, a composite `q` may pass randomized Miller–Rabin/Lucas checks.
Choose a factorable subgroup: if `g` has small order `q1 | q`, then
`y = g^x` exposes `x mod q1` with baby-step/giant-step or Pohlig–Hellman.
That residue can be enough to forge a signature whenever the verification key
only depends on `g^x` and `g` has the same small order.  Always replay the exact
parameter-validation random stream and verify the final signature in a fresh
session; a plausible local signature is not evidence of a solved challenge.
