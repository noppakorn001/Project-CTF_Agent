# ECC linearity in small-message OT challenges

Use this playbook when a challenge accepts an attacker-controlled elliptic-curve
public key and a ciphertext pair `(R,S)`, then returns a homomorphic expression
such as

`m0 * (1-C) + m1 * C`.

## Deterministic reduction

If the submitted public key is `H = hG`, the decryption relation is

`S - hR = (1-t)m0 + t m1`,

when the supplied ciphertext encodes choice scalar `t`.  Choose an injective
small integer `t` (for decimal messages `0..9`, `t=10` is sufficient), build a
bounded lookup table for all 100 possible pairs, and verify every response
against the curve relation before answering.

The point-at-infinity public key is often accepted when the server checks only
`H != G`; it makes `rH` cheap.  A crafted pair `(R,S)=(O,10G)` then exposes
`-9*m0 + 10*m1` directly.  If infinity is rejected, use a known scalar
`H=hG` and `(R,S)=(G,(t-h)G)` instead.

## Protocol and performance checks

- Parse JSON after the no-newline `input(prompt)` text; a response may be
  `prompt + JSON` on one line.
- Do not wait for the next prompt when the protocol is line-oriented.  Send the
  next choice immediately after the recovered-message line, while preserving
  line order.
- Keep the client table bounded and independent of the flag.  Record the full
  transcript and require all rounds before accepting a candidate.
- If the service performs several fresh random scalar multiplications per round,
  measure its wall-clock cutoff separately.  A correct algebraic exploit can
  still be operationally unfinishable; retain the partial-round evidence and do
  not promote a guessed flag.

## Verification invariant

For each recorded response, independently recompute

`S - hR == ((1-t)m0 + t*m1)G`.

Also require the exact allowlisted endpoint, the expected number of rounds, the
message range, and a flag returned by that same complete transcript.
