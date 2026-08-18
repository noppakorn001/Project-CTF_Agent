# Weak inner-product PRF stages

Some CTF services expose

```text
F_k(x) = ( <k,x> mod p + <k,x> mod q ) mod p
```

alongside a cached random function and let the operator guess which mode is
active.  The two functions must be evaluated through the same cache path, so a
repeat of one input is not a distinguisher.

Reusable routes:

1. For small `(p,q)=(2,3)`, query many distinct low-weight vectors and use the
   output distribution/weight-1 distinguisher. For `(5,7)`, the PRF output is
   noticeably non-uniform; a bounded sample and a pre-set frequency threshold
   distinguishes it from the random mode.
2. For `((<k,x> mod 5) mod 2)`, a `1` output implies the inner product is 1 or
   3 modulo 5. Linearize it as
   `(dot(k,x)-1)(dot(k,x)-3)=0 (mod 5)`, expand monomials of degree at most two,
   solve the resulting bounded GF(5) rank system, and replay all observations.
3. For large `p` and smaller `q`, each output gives an interval of width `q`
   for a linear combination modulo `p`. Build the square interval-lattice
   system, scale fixed/variable bounds, reduce with LLL, and apply Babai CVP.
   Recover the key from the identity columns and check every original interval
   before sending it.

Always batch queries, cap sample counts and matrix dimensions, and preserve the
full transcript. The route is based on the author's
[CODEGATE 2022 Dark Arts write-up](https://rkm0959.tistory.com/247); it is a
method reference, not an unverified flag.
