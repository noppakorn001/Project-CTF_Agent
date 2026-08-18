# NumPy RandomState seed rainbow tables

Signals: `numpy.random.seed`, `RandomState.bytes`, 32-bit `os.urandom` seed,
AES key/IV derived directly from PRNG output.

Route: reproduce legacy MT19937 initialization and `bytes()`'s little-endian
uint32 serialization; build a bounded table for a seed fraction (normally
`2^26` of the 32-bit space); match a six-byte output prefix; decrypt and use
padding/flag syntax to reject prefix collisions.  For nested encryption, the
first decrypted layer reveals the next IV and the same table lookup is applied
again.

Guardrails: cap seed limit, attempts, worker count, and socket timeout.  Keep
the exact ciphertext and both seeds in a replay record.  Independently
re-encrypt the candidate through every layer before calling it verified.

Reference implementation:
`ctf_challenges/cryptohack_archive/solvers/2021_import_numpy_as_mt_solve.py`.
