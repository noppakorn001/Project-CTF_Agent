# Pwn archetypes

Use one route at a time. Every proof is local, bounded, and tied to the artifact and
runtime hashes. A crash alone is not a primitive.

## Stack overwrite and code reuse

| Item | Route |
| --- | --- |
| Evidence | A length reaches a local stack object; a saved control value or adjacent local changes at a repeatable offset. |
| Cheapest proof | Send a cyclic-sized, bounded input; stop at the fault and map the observed overwrite to the input offset. Then demonstrate only the smallest intended control transfer. |
| Preconditions | Match architecture, calling convention, endianness, stack alignment, NX, PIE/ASLR, canary, and available executable/code-reuse targets. Treat a non-executable stack as ruling out injected-stack-code plans. |
| Stop | Stop after two offsets fail to reproduce, a canary terminates before control, or required addresses cannot be derived under the supplied runtime. |
| Verify | Re-run from a clean process with exact bytes and timeout; record the reached address and the mitigation/runtime facts. |

## Format-string read or write

| Item | Route |
| --- | --- |
| Evidence | Controlled text becomes a format argument; output changes with positional conversions or width/precision, rather than merely echoing. |
| Cheapest proof | Use a short positional marker to establish the argument index and whether a bounded read occurs. Prove one chosen write only against a disposable local target value. |
| Preconditions | Establish formatter, argument ABI, input truncation/NUL handling, output length, and whether `%n` is permitted. Account for PIE/ASLR and RELRO before proposing pointer or GOT changes. |
| Stop | Stop after two stable samples show literal handling, the index changes without an explained input-layout cause, or the necessary write is blocked. |
| Verify | Repeat the same index and byte count in a fresh process; save only the minimal transcript and observed value. |

## Dynamic-linking or indirect-call redirection

| Item | Route |
| --- | --- |
| Evidence | A writable function pointer, virtual dispatch entry, callback, or relocation-derived slot is reachable after a demonstrated write. ELF imports/relocations identify the candidate; they do not prove writability. |
| Cheapest proof | Resolve the candidate address from the exact binary/runtime and show one local benign redirection to an already intended function. |
| Preconditions | Establish PIE base, relocation type, RELRO state, symbol availability, and supplied loader/libc hashes. Full RELRO normally removes a writable GOT route; do not assume a host-libc offset. |
| Stop | Stop if the target is read-only, the pointer cannot be written by the proven primitive, or the runtime mapping differs from the supplied one. |
| Verify | Reproduce the mapping calculation and redirection from a new process; retain the relocation/symbol evidence. |

## Heap lifetime and metadata corruption

| Item | Route |
| --- | --- |
| Evidence | An allocation/free sequence produces an observable stale reference, double release, size confusion, or out-of-bounds neighbor change. |
| Cheapest proof | Minimize the menu/API sequence and show a single deterministic allocation-state or adjacent-byte effect; use the exact supplied allocator. |
| Preconditions | Record glibc/allocator version, allocation sizes, thread/arena use, tcache behavior, and ASLR. Do not transfer old allocator assumptions or removed interfaces across versions. |
| Stop | Stop when the minimal sequence is not repeatable, allocator checks abort before the claimed effect, or no usable read/write/control primitive follows. |
| Verify | Run the minimal sequence twice in fresh processes and confirm the same allocation ordering and byte-level result. |

## Parser, integer, or semantic primitive

| Item | Route |
| --- | --- |
| Evidence | A length, index, signedness conversion, state transition, or authorization-like check conflicts with the actual buffer/object bounds or intended operation. |
| Cheapest proof | Reduce to a valid framed request that shows one out-of-range read/write or one forbidden state transition without relying on a crash. |
| Preconditions | Model parsing width, byte order, length caps, integer promotion, retries, and protocol state. Keep inputs within the supplied service's intended scope. |
| Stop | Stop if independent framing checks reject the request, the discrepancy is only cosmetic, or two minimized inputs give no effect. |
| Verify | Replay the exact request from a clean local instance and assert the specific state/value change. |

## Syscall sandbox or seccomp boundary

| Item | Route |
| --- | --- |
| Evidence | The challenge supplies a sandbox profile, seccomp filter, namespace boundary, or explicit syscall protocol. |
| Cheapest proof | Inspect the filter/profile and trace a single benign allowed/denied syscall in a disposable VM; correlate the trace with the supplied binary. |
| Preconditions | Exact kernel/runtime and profile are available, process is non-root, and no host namespace, filesystem, socket, or secret is shared. Never use the host kernel as the lab. |
| Stop | Stop when no isolated runtime exists, the required syscall cannot be bounded, or the effect would escape the challenge workspace. |
| Verify | Repeat from a clean VM with a syscall trace and assert only the expected return/error and challenge-local output. |

## Kernel or system exploitation fixture

| Item | Route |
| --- | --- |
| Evidence | A supplied kernel image/module and disposable VM expose a documented challenge interface plus a reproducible mitigation/runtime fingerprint. |
| Cheapest proof | Inventory symbols, module parameters, permissions, and the exact VM boundary; prove one harmless read-only interaction before reasoning about a primitive. |
| Preconditions | Disposable non-privileged VM, no host mounts/secrets/network, exact kernel hash, and an explicit CTF scope. Do not load modules or alter the host kernel. |
| Stop | Stop if the VM boundary or source/runtime fingerprint is missing, or if the path requires host privilege or unbounded timing. |
| Verify | Re-run the bounded interaction in a fresh VM and preserve kernel/module hashes, trace, and challenge-local evidence. |

## Primary references

- [ELF format and program/section/relocation structures (Linux `elf(5)`)](https://man7.org/linux/man-pages/man5/elf.5.html)
- [GDB breakpoints and watchpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints.html) and [bounded process recording](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html)
- [pwntools ELF API](https://docs.pwntools.com/en/stable/elf/elf.html), [tubes/process and remote I/O](https://docs.pwntools.com/en/stable/tubes.html), and [ROP API](https://docs.pwntools.com/en/stable/rop/rop.html)
- [GNU allocator overview](https://sourceware.org/glibc/manual/latest/html_node/The-GNU-Allocator.html)
- [pwn.college software exploitation](https://pwn.college/software-exploitation/): format strings, allocator, exploitation primitives, and kernel modules for isolated practice.
- [pwn.college kernel exploitation](https://pwn.college/software-exploitation/kernel-exploitation): VM/kernel boundary cues; never copy its commands to a host system.
