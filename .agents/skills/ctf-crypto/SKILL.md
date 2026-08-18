---
name: ctf-crypto
description: Solve authorized CTF cryptography challenges involving RSA, ECC/signatures, block or stream ciphers, hashes/MACs, encodings, Diffie-Hellman, zero-knowledge transcripts, isogenies, bounded lattice leakage, and custom algebra. Reconstruct the exact local scheme, test evidenced flaws with bounded deterministic scripts, and independently verify recovery; never use unbounded brute force or submit flags.
---

# CTF Crypto

Read [playbook.md](references/playbook.md) before selecting a method. It contains
evidence gates, cheap checks, stop conditions, verification relations, and primary
source links for the supported archetypes.

1. Preserve supplied values and normalize them to bytes/integers with recorded
   encoding, length, endianness, modulus/curve, and operation order.
2. Use only facts present in the supplied implementation or samples to select a
   playbook route; prose is not evidence.
3. Set an operation, memory, and wall-time cap before any enumeration. Prefer
   exact arithmetic, pairwise relations, and known-plaintext checks.
4. Write the smallest deterministic recovery script in the challenge workspace;
   retain inputs, assumptions, and all sample checks.
5. Reproduce the result from clean inputs, then send any candidate to the
   independent verifier. Never submit it automatically.
