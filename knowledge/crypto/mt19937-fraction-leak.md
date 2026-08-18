# MT19937 partial-output leakage through exact fractions

Signal: a service scores a zero (or otherwise known) guess with a reduced
`Fraction(2**53, int(2**53 * random.random()) - known)` and later accepts
predictions.  The reduced numerator is a power of two; multiplying the
denominator by the corresponding power of two reconstructs the exact 53-bit
`random.random()` integer.

Cheap checks:

1. Confirm the denominator is positive and the numerator is a power of two;
   treat the capped score as an unknown output, not as a zero value.
2. Split each recovered integer as `(word0 >> 5) << 26 | (word1 >> 6)` and
   retain all 27 + 26 exposed bits.
3. Confirm the exact CPython MT variant.  A freshly seeded generator starts at
   index 624, and CPython's twist mutates the state in place in its wrap loop;
   do not substitute a batch/pure twist or a NumPy layout.

Bounded route: collect at most the service's documented rounds (1,000 in the
Real Mersenne instance), solve the linear temper/twist equations over GF(2),
and predict only the remaining rounds.  Stop on an inconsistent transcript,
too many capped observations, or a prediction mismatch; retry a fresh instance
instead of silently dropping arbitrary rows.

Verification: replay every non-capped observation, then compare at least one
withheld output (preferably the full remaining transcript) before decoding a
flag.  Use a separate implementation on a fresh allowlisted connection.
