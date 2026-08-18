# Isolated execution boundary for advanced CTF artifacts

Dynamic pwn, reverse, APK, firmware, and challenge-service work must not run on the
operator host. The application currently performs only read-only deterministic parsing;
this document defines the required boundary before an execution runner is enabled.

## Operator-provided runtime

The runner must use an operator-provided, locally available Docker image or disposable
VM snapshot. A missing image must fail closed; it may be built or pulled only after an
operator explicitly authorizes that separate setup action. It must never start an
interactive shell or execute a challenge binary merely because a challenge was
imported. The operator must explicitly approve each dynamic run after checking
category, artifact hash, budget, and scope.

The minimum container invocation policy is:

```text
network: none
root filesystem: read-only
user: non-root numeric UID/GID
capabilities: drop all
privilege escalation: disabled
pid limit: 64 or lower
memory limit: 512 MiB or lower
CPU limit: 1 core or lower
workspace: fresh tmpfs, no host home/secrets mounts
artifact mount: read-only, one challenge workspace only
timeout: explicit, short, action-specific
```

Do not mount the Docker socket, host root, `/proc` with elevated access, SSH material,
browser data, environment files, or any writable host directory. Kernel/module work
requires a disposable VM, not a container.

## Execution ladder

1. Read-only parsing first: artifact hashes, format metadata, bounded strings, ELF
   headers/relocations, archive structure, or protocol fixtures.
2. Local deterministic reimplementation second: decoded transform, exact crypto
   relation, or parser-state check.
3. Isolated dynamic trace third: one binary, fixed input, fixed timeout, no network.
4. Exploit proof only after a local primitive is reproducible and an operator explicitly
   approves the exact challenge workspace/runtime.
5. Remote interaction only after local reproduction and exact target allowlisting; a
   successful candidate is never auto-submitted.

## Runner contract

An advanced runner should receive structured data, not a free-form shell command:

```json
{
  "challenge_id": "ctf-...",
  "artifact_sha256": "...",
  "action": "static_elf_inspect | bounded_trace | verifier_replay",
  "input_sha256": "...",
  "timeout_seconds": 5,
  "memory_limit_mib": 256,
  "network": false,
  "operator_approved": true
}
```

It must emit a bounded JSON record containing artifact/runtime hashes, action, exit
status, timeout/resource result, redacted output digest, concise facts, and a verifier
relation. It must not return arbitrary raw logs, shell sessions, credentials, or a
network-derived flag.

## Category gates

| Category | First runnable proof | Do not enable without |
| --- | --- | --- |
| Pwn | fixed local process plus bounded crash/primitive trace | exact loader/libc, disposable runtime, no host mount/network |
| Reverse | fixed input trace or bounded emulator | architecture/runtime match and original/derived artifact hashes |
| APK/JNI | static inventory first, then isolated emulator trace | supplied APK, ABI/API match, no personal account/device data |
| Firmware | bounded static extraction | disposable emulator/VM and known architecture/load address |
| Web | supplied source or local intentionally vulnerable lab | exact allowlist, no third-party/metadata/loopback access |

Until this contract is implemented and a runtime is explicitly configured, these routes
remain analysis/planning only. This is intentional: Docker by itself is not a complete
boundary for hostile binaries.
