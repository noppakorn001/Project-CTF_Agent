"""Offline registry of reusable CTF cryptography workflows.

The registry is deliberately data-first: it helps an operator choose an
evidence-gated route and locate an existing solver, but it never executes a
solver, opens a socket, or submits a flag.  Challenge directories remain the
source of truth for artifacts, transcripts, and challenge-specific assumptions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class Playbook:
    """One evidence-gated route and its closest local example."""

    id: str
    family: str
    title: str
    evidence: str
    first_check: str
    verify: str
    script: str | None = None
    usage: str | None = None
    signals: tuple[str, ...] = ()
    network_required: bool = False
    runner: str = "python3"

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["signals"] = list(self.signals)
        return value

    @property
    def status(self) -> str:
        return "network-gated" if self.network_required else "offline"

    def command(self, root: Path = REPO_ROOT) -> str:
        """Return a copyable command template; do not run it here."""

        if not self.script:
            return "No bundled solver; create a bounded workspace solver from the route."
        path = root / self.script
        usage = "[challenge input]" if self.usage is None else self.usage
        return f"{self.runner} {path} {usage}".rstrip()


# Each script was already exercised in a supplied picoCTF/CyLab workspace; the
# registry only points to the script and does not claim that a new challenge
# satisfies the route's prerequisites.  ``list_playbooks`` supplies stable
# family/id ordering for the CLI and JSON consumers.
PLAYBOOKS: tuple[Playbook, ...] = (
    Playbook(
        "classical/atbash",
        "classical",
        "Atbash substitution",
        "The artifact names Atbash or an involutive A<->Z substitution is evidenced.",
        "Apply the involution to a bounded text and require one flag-shaped result.",
        "Re-run from the original artifact hash and compare the exact decoded bytes.",
        "ctf_challenges/picoctf2023_crypto/hidetosee/solve.py",
        "",
        signals=("atbash", "a<->z", "mirror alphabet"),
    ),
    Playbook(
        "classical/caesar",
        "classical",
        "Caesar / rotation",
        "A named monoalphabetic rotation or a fixed shift is present in the source/text.",
        "Enumerate exactly 26 shifts; keep all candidates until format and context select one.",
        "Apply the selected shift again to the original bytes and retain the candidate list.",
        "ctf_challenges/picoctf2019_crypto/caesar/solve.py",
        "[ciphertext-file]",
        ("caesar", "rotation", "rot", "shift"),
    ),
    Playbook(
        "classical/morse",
        "classical",
        "Morse transcription",
        "The artifact is a bounded stream of dot/dash tokens or explicitly names Morse.",
        "Decode tokens locally, preserving unknown tokens for review.",
        "Decode the original transcript again and compare token count and exact output.",
        "ctf_challenges/picoctf2019_crypto/tapping/solve.py",
        "[transcript-file]",
        ("morse", "dot dash", "tapping"),
    ),
    Playbook(
        "classical/substitution",
        "classical",
        "Monoalphabetic substitution",
        "A substitution mapping, frequency signal, or known plaintext is evidenced.",
        "Build a bounded mapping and check punctuation/flag prefix without online solvers.",
        "Re-encrypt the recovered text with the complete mapping and check every symbol.",
        "ctf_challenges/picoctf2022_crypto/substitution1/solve.py",
        "",
        ("substitution", "frequency", "monoalphabetic", "mapping"),
    ),
    Playbook(
        "classical/vigenere",
        "classical",
        "Vigenere / Bellaso",
        "The key, tableau, or repeating-key alphabetic stream is evidenced.",
        "Advance the key over letters only and preserve punctuation/case.",
        "Encrypt the candidate with the same key and compare the complete ciphertext.",
        "ctf_challenges/picoctf2019_crypto/la_cifra_de/solve.py",
        "[ciphertext-file] [key]",
        ("vigenere", "vignere", "bellaso", "repeating key"),
    ),
    Playbook(
        "encoding/base64-chain",
        "encoding",
        "Strict chained Base64/text decoding",
        "The source or artifact explicitly applies Base64 one or more times.",
        "Strict-decode each layer, recording byte lengths and rejecting malformed padding.",
        "Re-encode every layer and compare the original bytes before accepting a flag.",
        "ctf_challenges/picoctf2024_crypto/interencdec/solve.py",
        "",
        signals=("base64", "b64", "encoding", "decode"),
    ),
    Playbook(
        "rsa/crt-fault",
        "rsa",
        "CRT-RSA fault / algebraic recovery",
        "The implementation exposes faulty CRT outputs or a related polynomial equation.",
        "Derive the exact relation and compute a bounded gcd or polynomial check.",
        "Re-encrypt/replay every supplied sample and verify the recovered factors/equations.",
        "ctf_challenges/picoctf2021_crypto/its_not_my_fault_1/solve.py",
        "--host HOST --port PORT",
        signals=("crt", "fault", "dp", "dq", "polynomial"),
        network_required=True,
    ),
    Playbook(
        "rsa/exact-low-exponent",
        "rsa",
        "Low-exponent exact root",
        "RSA uses a small exponent and the unpadded representative is small enough for an exact root.",
        "Try an exact integer root first, then a declared small k*n lift cap.",
        "Raise the recovered plaintext with the original exponent and compare modulo n.",
        "ctf_challenges/picoctf2019_crypto/mini_rsa/solve.py",
        "[transcript-file]",
        ("rsa", "small exponent", "e=3", "cube root", "low exponent"),
    ),
    Playbook(
        "rsa/multiplicative-oracle",
        "rsa",
        "RSA multiplicative / no-padding oracle",
        "A challenge oracle returns a valid decryption of a chosen multiplied ciphertext.",
        "Use one bounded multiplier and validate parity/wrap before decoding bytes.",
        "Check the oracle relation, then replay the local plaintext derivation independently.",
        "ctf_challenges/picoctf2024_crypto/rsa_oracle/solve.py",
        "",
        ("rsa", "oracle", "multiplicative", "no padding", "chosen ciphertext"),
        True,
    ),
    Playbook(
        "rsa/multi-prime",
        "rsa",
        "Multi-prime RSA",
        "The modulus is supplied with an explicit prime list or a bounded factorization signal.",
        "Validate that every supplied factor is positive and that their product equals n.",
        "Recompute phi/lambda, decrypt, and re-encrypt with the complete factor list.",
        "ctf_challenges/picoctf2019_crypto/b00tl3g_rsa3/solve.py",
        "[transcript-file]",
        ("rsa", "multi-prime", "many primes", "factors"),
    ),
    Playbook(
        "rsa/pollard-p-minus-1",
        "rsa",
        "Pollard p-1 factorization",
        "A supplied modulus has a smooth p-1 bound or the source exposes that structure.",
        "Set a finite smoothness bound before computing the gcd.",
        "Multiply recovered factors back to n and verify RSA decryption/re-encryption.",
        "ctf_challenges/picoctf2022_crypto/very_smooth/solve.py",
        "",
        signals=("pollard", "p-1", "smooth", "factor"),
    ),
    Playbook(
        "rsa/shared-prime-gcd",
        "rsa",
        "Shared-prime GCD",
        "Two or more RSA moduli are supplied and may share a prime.",
        "Compute pairwise gcds before attempting any factor search.",
        "Check p*q equals each affected modulus and validate the recovered private key.",
        "ctf_challenges/picoctf2021_crypto/mind_your_ps_and_qs/solve.py",
        "",
        signals=("rsa", "shared prime", "gcd", "moduli"),
    ),
    Playbook(
        "rsa/wiener-small-d",
        "rsa",
        "Wiener continued-fraction attack",
        "The source or parameters evidence an unusually small private exponent d.",
        "Enumerate convergents of e/n under the stated Wiener bound.",
        "Check p*q=n and both RSA key equations before decoding the message.",
        "ctf_challenges/picoctf2021_crypto/dachshund_attacks/solve.py",
        signals=("rsa", "wiener", "small d", "continued fraction"),
    ),
    Playbook(
        "side-channel/cpa-aes",
        "side-channel",
        "AES S-box power-analysis / CPA",
        "Traces correlate with Hamming weight of Sbox[plaintext XOR key].",
        "Use the bounded trace window and score all 256 byte hypotheses.",
        "Replay the correlation on clean traces and verify the complete key-derived flag.",
        "ctf_challenges/picoctf2023_crypto/poweranalysis_part1/solve.py",
        "",
        signals=("power", "trace", "cpa", "sbox", "side channel", "hamming weight"),
    ),
    Playbook(
        "stream/otp-keystream-reuse",
        "stream",
        "OTP / stream keystream reuse",
        "Two messages demonstrably reuse key material or a known plaintext alignment.",
        "Check C1 XOR C2 equals P1 XOR P2 over the exact overlap.",
        "Recreate every ciphertext from the recovered keystream and check lengths.",
        "ctf_challenges/picoctf2021_crypto/easy_peasy/solve.py",
        "--host HOST --port PORT",
        signals=("otp", "one-time pad", "keystream", "xor", "nonce reuse"),
        network_required=True,
    ),
    Playbook(
        "authenticated-stream/chacha20-poly1305-reuse",
        "authenticated-stream",
        "ChaCha20-Poly1305 nonce reuse",
        "Two authenticated packets share an exact nonce and at least one plaintext is known.",
        "Recover the aligned keystream, then solve the bounded Poly1305 tag-difference polynomial.",
        "Recompute the forged ciphertext/tag and cleanly decrypt/verify it on the same transcript.",
        "ctf_challenges/chacha_slide/solve.py",
        "",
        signals=("chacha20", "poly1305", "authenticated", "nonce reuse", "tag"),
    ),
    Playbook(
        "block/des-meet-in-the-middle",
        "block",
        "Double-DES meet-in-the-middle",
        "Double DES exposes a chosen plaintext/ciphertext pair and independent 56-bit keys.",
        "Build bounded forward/backward tables and cap memory/key iterations.",
        "Re-encrypt a second target under both recovered keys.",
        "ctf_challenges/picoctf2021_crypto/double_des/solve.py",
        "--host HOST --port PORT",
        ("des", "double des", "meet in the middle", "mitm"),
        True,
    ),
    Playbook(
        "oracle/compression-length",
        "oracle",
        "Compression-length oracle",
        "The oracle returns ciphertext lengths after compressing attacker input with a secret.",
        "Batch a finite alphabet per round and retain tied minima; stop at the query cap.",
        "Replay the recovered prefix against the same recorded length relation.",
        "ctf_challenges/picoctf2021_crypto/compress_and_attack/solve.py",
        "--host HOST --port PORT",
        ("compression", "zlib", "length oracle", "oracle"),
        True,
    ),
    Playbook(
        "custom/algebraic-encryption",
        "custom",
        "Custom modular / algebraic encryption",
        "The challenge source defines equations not matching a standard primitive.",
        "Write the equations from the actual code and test dimensions/rank/invertibility first.",
        "Substitute the candidate into every original equation and regenerate samples.",
        "ctf_challenges/picoctf2024_crypto/custom_encryption/solve.py",
        "",
        signals=("custom encryption", "algebra", "modular", "equation"),
    ),
    Playbook(
        "custom/sra-omitted-modulus",
        "custom",
        "SRA omitted-modulus recovery",
        "The source exposes c,d and the relation ed-1=k(p-1)(q-1) while n is hidden.",
        "Enumerate only the evidenced finite factor/divisor space with a time cap.",
        "Recompute c=m^e mod n for the recovered factors and exact byte encoding.",
        "ctf_challenges/picoctf2023_crypto/sra/solve.py",
        "",
        signals=("sra", "omitted modulus", "ed-1", "rsa"),
    ),
    Playbook(
        "custom/unreduced-key-exchange",
        "custom",
        "Unreduced custom key-exchange multiplication",
        "Both public reduced sums are exposed and the final ciphertext is an exact unreduced integer multiple of the derived shared key.",
        "Simplify both exchange branches symbolically, derive the shared value modulo p, and test exact divisibility before any inversion.",
        "Recompute the shared value from the original parameters and multiply the recovered bytes back to the exact ciphertext.",
        "ctf_challenges/cryptohack_archive/solvers/2021_a_joke_cipher_solve.py",
        "[output.txt]",
        signals=("custom", "key exchange", "unreduced", "exact multiple", "shared key"),
    ),
    Playbook(
        "encoding/known-plaintext-xor",
        "encoding",
        "Known-plaintext XOR / custom reversible layer",
        "The implementation shows XOR against a repeating key or known plaintext.",
        "Recover only the aligned key bytes and check the exact overlap.",
        "Reapply the transform to the complete artifact and compare all bytes.",
        "ctf_challenges/picoctf2024_crypto/custom_encryption/solve.py",
        "",
        signals=("xor", "known plaintext", "repeating key", "custom"),
    ),
    Playbook(
        "interpolation/consecutive-points",
        "interpolation",
        "Fast finite-field interpolation",
        "The artifact has a large consecutive x=0..n stream and the naive code builds a Vandermonde matrix.",
        "Preserve/hash the full artifact, then use a product tree and derivative weights without an n×n matrix.",
        "Substitute recovered coefficients into sampled original points and validate the downstream artifact.",
        "ctf_challenges/picoctf2024_crypto/flag_printer/solve_fast.sage",
        "",
        ("interpolation", "consecutive points", "vandermonde", "finite field"),
        False,
        "sage",
    ),
    Playbook(
        "lattice/bounded-modular-leakage",
        "lattice",
        "Bounded modular leakage / LLL",
        "The source exposes bounded coefficients, partial leakage, or noisy modular equations.",
        "Estimate dimension, modulus, and bounds before constructing a finite lattice.",
        "Substitute the candidate into every original equation and rerun the bounded reduction.",
        "ctf_challenges/mss_advance/solve.py",
        "[challenge-output]",
        ("lattice", "lll", "partial leakage", "bounded", "modular equations"),
    ),
    Playbook(
        "protocol/interactive-rsa-quiz",
        "protocol",
        "Interactive RSA arithmetic client",
        "The instance presents explicit RSA arithmetic prompts and accepts one answer per prompt.",
        "Parse only bounded prompts and answer n, phi, e, d, encrypt, and decrypt relations exactly.",
        "Replay all answers from the saved transcript and convert the final integer with the stated encoding.",
        "ctf_challenges/picoctf2019_crypto/rsa_pop_quiz/client.py",
        "HOST PORT",
        ("rsa", "quiz", "interactive", "prompt", "phi"),
        True,
    ),
    Playbook(
        id="authenticated-stream/aes-gcm-ghash",
        family="authenticated-stream",
        title="AES-GCM GHASH nonce reuse / tag forgery",
        evidence="The source reuses a GCM nonce, exposes a tag relation, or implements GHASH incorrectly.",
        first_check="Compare nonce lengths and repeated nonces first; then derive the exact GHASH block layout from the supplied code.",
        verify="Recompute ciphertext, AAD, GHASH, and tag from the recovered subkey or forgery relation on an independent transcript.",
        signals=("aes-gcm", "gcm", "ghash", "nonce reuse", "tag forgery"),
    ),
    Playbook(
        id="ecc/ecdsa-dsa-nonce",
        family="ecc",
        title="ECDSA/DSA nonce reuse or partial nonce leakage",
        evidence="Two signatures reuse k, leak a nonce bit pattern, or expose a deterministic nonce state.",
        first_check="Normalize r,s,z and curve/order parameters, reject duplicate or malformed signatures, then test exact nonce-reuse algebra.",
        verify="Check the recovered private key against every original signature and derive a fresh signature without submitting it.",
        signals=("ecdsa", "dsa", "signature", "nonce", "k reuse", "private key"),
    ),
    Playbook(
        id="signature/dsa-composite-q",
        family="signature",
        title="DSA composite-q / seeded-primality subgroup leak",
        evidence="The client chooses DSA parameters and a seed controls os.urandom or randomized primality checks; q has a small factor and g is confined to that subgroup.",
        first_check="Replay the exact seeded parameter-validation calls, factor only the evidenced small q component, and recover x modulo that subgroup order with a bounded discrete-log method.",
        verify="Recompute y=g^x, make a raw signature for the fixed message, and require a fresh independent service replay before recording a flag.",
        script="ctf_challenges/cryptohack_archive/solvers/2023_unrandom_dsa_solve.py",
        usage="--timeout 120",
        signals=("dsa", "composite q", "seeded primality", "small subgroup", "pohlig-hellman", "baby-step giant-step"),
        network_required=True,
    ),
    Playbook(
        id="ecc/invalid-curve-or-subgroup",
        family="ecc",
        title="ECC invalid-curve / small-subgroup confinement",
        evidence="The implementation accepts attacker-supplied points without curve, order, or subgroup validation.",
        first_check="Validate point encoding and curve equation locally, then enumerate only the explicitly evidenced small subgroup orders.",
        verify="Recompute the shared point under the original validation path and combine only independently consistent residues.",
        signals=("ecc", "elliptic curve", "invalid curve", "small subgroup", "twist", "point validation"),
    ),
    Playbook(
        id="ecc/quadratic-twist-smooth-order",
        family="ecc",
        title="Quadratic-twist smooth-order x-only ladder",
        evidence="An x-only ladder accepts arbitrary x values and a nonsquare RHS can be lifted to a quadratic twist with factored order.",
        first_check="Use a bounded nonsquare x probe, factor the selected twist point order, and solve only the evidenced prime components with Pohlig–Hellman/BSGS.",
        verify="Replay the exact integer ladder from the recorded scalar and require the response x-coordinate and flag bytes to match.",
        script="ctf_challenges/cryptohack_archive/solvers/2023_twist_and_shout_solve.py",
        usage="--timeout 60 --record PATH",
        signals=("ecc", "x-only", "quadratic twist", "invalid x", "pohlig-hellman", "smooth order"),
        network_required=True,
    ),
    Playbook(
        id="ecc/dh-public-key-reuse-xor",
        family="ecc",
        title="DH public-key reuse with XOR keystream recovery",
        evidence="A DH endpoint accepts a supplied public point and XOR-encrypts a known quote, while the flag flow returns C1=rG and C2=flag XOR rP.",
        first_check="Replay C1 as the supplied DH point; XOR each known quote candidate and require exactly one resulting coordinate pair on the stated curve.",
        verify="Recompute the curve equation, derive the keystream from the unique quote, and compare the recovered flag against the recorded C2 bytes and independent transcript.",
        script="ctf_challenges/cryptohack_archive/solvers/2022_pekobot_solve.py",
        usage="--timeout 20 --record PATH",
        signals=("ecc", "diffie-hellman", "public key reuse", "xor", "known plaintext", "pekobot"),
        network_required=True,
    ),
    Playbook(
        id="secret-sharing/shamir-interpolation",
        family="secret-sharing",
        title="Shamir secret sharing / finite-field interpolation",
        evidence="The challenge supplies distinct (x,y) shares and a field modulus or threshold relation.",
        first_check="Check share count, coordinate uniqueness, modulus bounds, and whether the field operations are actually prime-field arithmetic.",
        verify="Substitute the recovered polynomial back into every supplied share and independently evaluate the secret at the required point.",
        signals=("shamir", "secret sharing", "shares", "threshold", "lagrange", "finite field"),
    ),
    Playbook(
        id="prng/mt19937-state-recovery",
        family="prng",
        title="MT19937 output untempering / state recovery",
        evidence="At least 624 consecutive full-width MT19937 outputs, or a bounded partial-output wrapper such as exact 53-bit Python random observations, are available.",
        first_check="Confirm the generator variant, output width, seed/index convention, and twist mutation order; untemper full outputs or model every exposed partial bit, and never assume Python/numpy state layouts are interchangeable.",
        verify="Predict a withheld output from the recovered state and compare it before decoding any candidate flag.",
        signals=("mt19937", "mersenne", "numpy", "prng", "temper", "state"),
    ),
    Playbook(
        id="oracle/paillier-nonadaptive-padding",
        family="oracle",
        title="Non-adaptive Paillier padding oracle",
        evidence="The service encrypts a low-entropy message with Paillier, applies a weak PKCS#1 v1.5 unpad check, and returns a batch of validity bits.",
        first_check="Model the exact plaintext byte layout and homomorphic addition; build non-adjacent byte-equality queries because responses are not adaptive.",
        verify="Intersect all precomputed candidate partitions for every round and require a unique digest, then independently replay the recorded response vector before trusting the final flag.",
        script="ctf_challenges/cryptohack_archive/solvers/2022_maybe_someday_solve.py",
        usage="--timeout 30 --record PATH",
        signals=("paillier", "padding oracle", "pkcs#1", "non-adaptive", "homomorphic", "valid padding"),
        network_required=True,
    ),
    Playbook(
        id="prng/mt19937-offset-two-candidates",
        family="prng",
        title="MT19937 twist-offset two-candidate prediction",
        evidence="Two full-width outputs are chosen at indices that expose state[i+1] and state[i+397] immediately before a requested twist output.",
        first_check="Untemper both words, apply the twist recurrence, and enumerate only the unknown high bit of state[i]; do not brute-force the 32-bit seed.",
        verify="Require the submitted guess to equal one of the two independently recomputed candidates and retain the service transcript and flag response.",
        script="ctf_challenges/cryptohack_archive/solvers/2020_tetctf2020_solve.py",
        usage="--retries 8 --timeout 20 --record PATH",
        signals=("mt19937", "twist", "chosen indices", "two candidates", "getrandbits"),
        network_required=True,
    ),
    Playbook(
        id="prng/numpy-randomstate-seed-rainbow",
        family="prng",
        title="NumPy RandomState 32-bit seed rainbow table",
        evidence="The source calls legacy numpy.random.seed with a 32-bit seed and derives an IV/key directly from RandomState.bytes().",
        first_check="Reproduce MT19937 initialization, twist, tempering, and little-endian uint32 serialization; match a bounded seed fraction against a short IV prefix before decrypting.",
        verify="Re-encrypt the candidate through every nested CBC layer from recorded seeds and compare the exact service ciphertext; retain a bounded live transcript.",
        script="ctf_challenges/cryptohack_archive/solvers/2021_import_numpy_as_mt_solve.py",
        usage="--attempts 4096 --workers 32 --prefix-bytes 6 --record PATH",
        signals=("numpy", "randomstate", "random.bytes", "mt19937", "32-bit seed", "rainbow table"),
        network_required=True,
    ),
    Playbook(
        id="hash/custom-collision",
        family="hash",
        title="Hash collision / custom digest weakness",
        evidence="The challenge uses a short, truncated, custom, or structurally weak digest and accepts two distinct messages.",
        first_check="Reproduce the exact digest implementation and cap message length, search space, and collision work before generating candidates.",
        verify="Hash both original candidate messages from clean bytes and confirm the verifier's complete equality condition.",
        signals=("hash", "collision", "md5", "sha1", "truncated", "custom digest"),
    ),
    Playbook(
        id="hash/murmur3-bloom-universal-collision",
        family="hash",
        title="MurmurHash3 Bloom-filter universal collision",
        evidence="A Bloom filter inserts attacker-controlled bytes with MurmurHash3 under several fixed seeds, and one insertion can be queried through a separate admin path.",
        first_check="Use a bounded known universal multicollision pair, verify it with an independent MurmurHash3 implementation for every service seed, and confirm the admin-format predicates locally.",
        verify="Replay insertion and admin query on the exact allowlisted service, then independently check all seed digests, distinctness, and the recorded unique flag.",
        script="ctf_challenges/cryptohack_archive/solvers/2022_diffecient_solve.py",
        usage="--timeout 20 --record PATH",
        signals=("murmur3", "bloom filter", "universal collision", "hash collision", "diffecient"),
        network_required=True,
    ),
    Playbook(
        id="hash/base256-group-preimage",
        family="hash",
        title="Custom modular-exponent hash / lowercase base-256 preimage",
        evidence="The digest is g^int.from_bytes(prefix + message) mod p and consecutive byte queries are available.",
        first_check="Recover p from two consecutive-hash second differences; center lowercase bytes at 109 and build a bounded LLL lattice for the exponent congruence.",
        verify="Check every recovered byte is lowercase and directly compare modular exponents or hashes against the target before recording a flag.",
        signals=("custom hash", "discrete log", "group hash", "base256", "lowercase preimage", "LLL"),
    ),
    Playbook(
        id="custom/weak-prf-mode-and-key",
        family="custom",
        title="Weak inner-product PRF mode test and key recovery",
        evidence="The oracle chooses between a cached random function and (k·H(x) mod p + k·H(x) mod q) mod p, or reveals p/q and bounded linear outputs.",
        first_check="Use duplicate-safe distribution tests for the p=2,q=3 and p=5,q=7 stages; for a GF(5) parity wrapper linearize (dot(k,x)-1)(dot(k,x)-3)=0 and solve a bounded rank system; for the final stage build interval equations and use a CVP lattice.",
        verify="Replay every queried output under the recovered mode/key, check all key coordinates and modulus equations, then complete the challenge only after the clean transcript accepts.",
        signals=("weak prf", "inner product", "random function", "mode", "distribution", "cvp", "interval lattice"),
        network_required=True,
    ),
    Playbook(
        id="proof/zero-knowledge-transcript",
        family="proof",
        title="Zero-knowledge proof transcript / Fiat-Shamir weakness",
        evidence="The protocol exposes commitments/challenges with a repeated nonce, weak challenge derivation, or malleable transcript.",
        first_check="Parse a bounded transcript and verify the verifier equation before attempting a replay or extractor.",
        verify="Run the verifier over a clean transcript and check that the accepted proof satisfies every equation, not just a claimed flag field.",
        signals=("zero knowledge", "zk", "proof", "fiat-shamir", "commitment", "challenge"),
    ),
    Playbook(
        id="proof/groth16-rerandomisation",
        family="proof",
        title="Groth16 proof rerandomisation / ticket accounting",
        evidence="A service exposes an issued Groth16 proof and verification key, and counts accepted proof encodings as separate tickets.",
        first_check="Confirm the statement digest is fixed and apply only the public transform A' = r1^-1 A, B' = r1 B + r1 r2 delta_g2, C' = C + r2 A with nonzero bounded scalars.",
        verify="Require every fresh proof to be accepted by the live pairing verifier, check canonical point encodings and distinct ticket identities, then replay the balance arithmetic independently.",
        script="ctf_challenges/cryptohack_archive/solvers/2024_ticket_maestro_solve.py",
        usage="--timeout 30 --count 15 --record PATH",
        signals=("groth16", "rerandomization", "rerandomisation", "zk-snark", "ticket", "proof malleability"),
        network_required=True,
    ),
    Playbook(
        id="signature/ed25519-implementation",
        family="signature",
        title="Ed25519 implementation or verification mismatch",
        evidence="The source customizes Ed25519 encoding, scalar reduction, context, or verification rules.",
        first_check="Compare the exact byte encoding and reduction rules with the reference algorithm; preserve leading zeros and canonical checks.",
        verify="Verify the recovered signature/message pair with an independent implementation or a clean reference equation.",
        signals=("ed25519", "eddsa", "signature", "scalar", "canonical encoding"),
    ),
    Playbook(
        id="rsa/partial-key-leakage",
        family="rsa",
        title="RSA partial-key / leaked-bit recovery",
        evidence="The challenge leaks contiguous or bounded bits of p, q, d, or CRT parameters together with enough exact relations.",
        first_check="Write the leaked-bit equations and estimate the finite lattice dimension and bounds before constructing a lattice.",
        verify="Multiply recovered factors to n and validate all supplied RSA equations plus a fresh encrypt/decrypt round trip.",
        signals=("rsa", "partial key", "leaked bits", "known bits", "crt", "lattice"),
    ),
    Playbook(
        id="custom/complex-rsa-private-factors",
        family="custom",
        title="Complex RSA with supplied private factors",
        evidence="The output exposes factors of n=p²q² and the source exponentiates Gaussian-integer components modulo n.",
        first_check="Reconstruct the exact ring/group exponent from p mod 4 and q mod 4, then preserve the component byte width and source padding.",
        verify="Raise the recovered complex plaintext back to e=65537 and compare both ciphertext components before removing only the source separator.",
        script="ctf_challenges/cryptohack_archive/solvers/2021_unimplemented_complex_rsa_solve.py",
        usage="[output.txt]",
        signals=("complex rsa", "gaussian", "p^2", "q^2", "private factors", "unimplemented"),
    ),
)


def list_playbooks(
    *, category: str | None = None, search: str | None = None
) -> list[Playbook]:
    """Return deterministic registry matches without touching challenge data."""

    category_value = category.lower().strip() if category else None
    query = search.lower().strip() if search else None
    matches: list[Playbook] = []
    for playbook in PLAYBOOKS:
        if category_value and playbook.family != category_value:
            continue
        haystack = " ".join(
            (
                playbook.id,
                playbook.family,
                playbook.title,
                playbook.evidence,
                playbook.first_check,
                " ".join(playbook.signals),
            )
        ).lower()
        if query and query not in haystack:
            continue
        matches.append(playbook)
    return sorted(matches, key=lambda item: (item.family, item.id))


def get_playbook(identifier: str) -> Playbook:
    """Resolve one route or raise a useful error for CLI callers."""

    value = identifier.strip().lower()
    for playbook in PLAYBOOKS:
        if playbook.id == value:
            return playbook
    raise KeyError(f"unknown playbook: {identifier}")


def suggest_playbooks(text: str, *, limit: int = 5) -> list[tuple[Playbook, int]]:
    """Rank routes by explicit signal words in supplied text.

    This is a hint for triage only.  It never authorizes an action and does not
    replace the evidence gate in the crypto skill.
    """

    if limit < 1:
        raise ValueError("limit must be positive")
    haystack = text.lower()
    scored: list[tuple[int, Playbook]] = []
    for playbook in PLAYBOOKS:
        score = sum(1 for signal in playbook.signals if signal.lower() in haystack)
        if score:
            scored.append((score, playbook))
    scored.sort(key=lambda item: (-item[0], item[1].id))
    return [(playbook, score) for score, playbook in scored[:limit]]


def validate_playbooks(root: Path = REPO_ROOT) -> list[str]:
    """Return missing local solver paths; an empty list means the index is sound."""

    missing: list[str] = []
    for playbook in PLAYBOOKS:
        if playbook.script and not (root / playbook.script).is_file():
            missing.append(playbook.script)
    return missing


def serialise(playbooks: Iterable[Playbook]) -> list[dict[str, object]]:
    return [playbook.as_dict() for playbook in playbooks]
