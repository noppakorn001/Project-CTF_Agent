# Coppersmith for a prime in a known interval

Signal: an RSA modulus `n=pq` and a rounded algebraic hint gives a bound
`L <= q <= L+X`, where `X` is below roughly `n^(1/4)` for the unknown prime.

Bounded route: write `q=L+x`, so `f(x)=x+L` vanishes modulo `q`. Build a
small univariate Coppersmith basis from `x^j f(x)^i n^(m-i)` and scale the
coefficient of `x^j` by `X^j`. Reduce with exact LLL, remove the trivial
`x+L` factor if it appears in every short vector, and take the integer gcd of
two remaining polynomials. Check `q > 1`, `n % q == 0`, and all source relations
before using the factor.

Stop condition: do not scan the interval or increase lattice dimensions
indefinitely. Keep `m,t`, LLL precision, wall time, and memory bounded; if the
reduction does not yield a validated factor, record the challenge as pending.

Reference implementation: `ctf_challenges/cryptohack_archive/solvers/2020_1337crypt_solve.py`.
