# Custom algebraic crypto checks

## Unreduced shared-key multiplication

Signal: a custom exchange exposes reduced public values (`y_A`, `y_B`) and
the final encryption multiplies a message by a shared value without reducing
the ciphertext.

Cheap check: symbolically substitute the public-value definitions into both
exchange branches.  If both branches reduce to the same expression, derive it
modulo the supplied modulus and test exact ciphertext divisibility.  Cap all
integer sizes before converting recovered bytes.

Verification: multiply the recovered integer by the derived key and compare
the complete original ciphertext bytes/integers; then run an independent
verifier using a separately parsed copy of the output.  If divisibility fails,
stop rather than guessing a modular inverse.
