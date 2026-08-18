# Groth16 proof rerandomisation

When a verifier accepts Groth16 proofs for one fixed public statement, a valid
proof can be rerandomised without knowing the witness.  For Arkworks' BN254
implementation, with nonzero scalar-field values `r1,r2` and the verification
key's `delta_g2`:

```text
A' = r1^-1 A
B' = r1 B + r1*r2*delta_g2
C' = C + r2 A
```

This is not a forgery of a new statement; it is a fresh valid encoding of the
same statement.  It becomes a vulnerability only when an application treats
serialized proof bytes as unique bearer tickets or counts each accepted proof
as new value.  To verify a challenge replay, check the pairing acceptance on
the service, canonical point encodings, proof-identity uniqueness, and the
complete accounting relation independently.  Never infer success from a
flag-shaped client field alone.

