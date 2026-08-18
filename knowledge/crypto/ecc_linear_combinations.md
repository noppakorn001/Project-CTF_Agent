# ECC linear-combination transcripts

When a challenge publishes points `R_i = a_i P + b_i Q`, choose a pair whose
determinant is invertible modulo the known subgroup order and solve the 2x2
system in the group. If `Q = mP`, recover `m` with Pohlig--Hellman when the
order factors smoothly. For large curves, use Jacobian coordinates and batch
normalize BSGS tables; avoid one field inversion per baby/giant step.

Reference implementation: `ctf_challenges/cryptohack_archive/solvers/2023_hide_and_seek_solve.py`.
