# Invalid x-coordinate and smooth quadratic twist

When an x-only elliptic-curve ladder accepts arbitrary field elements, it may
evaluate a quadratic twist even if the x-coordinate is not on the advertised
curve.  Look for a small x whose RHS is a nonsquare, lift it into `F(q^2)`, and
factor the twist point order.  If the selected point order is smooth, use
Pohlig--Hellman with bounded BSGS per prime factor and CRT.

The local verifier must replay the exact integer x-only ladder against the
recorded scalar and response; do not accept a scalar merely because its flag
bytes look printable.  Keep the extension-field representation and chosen
twist point in the transcript so the result is reproducible.
