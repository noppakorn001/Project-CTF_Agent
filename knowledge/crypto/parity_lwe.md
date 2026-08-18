# Parity leakage in noisy modular dot products

For `c = <a,s> + e (mod 2^k)`, first check whether the error distribution has a
known parity. If `e` is always even, real samples leak `<a,s> mod 2`. Known
plaintext bits (for example ASCII MSBs) supply equations; solve the resulting
GF(2) system with Gaussian elimination. Classify candidate groups by parity
consistency before using higher-cost lattice/CVP machinery.

Reference implementation: `ctf_challenges/cryptohack_archive/solvers/2023_tough_decisions_solve.py`.
