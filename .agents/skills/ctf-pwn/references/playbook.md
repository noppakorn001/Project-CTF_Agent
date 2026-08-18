# Pwn challenge playbook

## Deterministic first pass

- `file` and SHA-256 for identity and architecture.
- Targeted `readelf -h -l -S -s -r` for ELF metadata, segments, symbols, and relocations.
- `objdump` or a decompiler only around entry points, imported sinks, and referenced
  strings; do not dump the whole binary into chat.
- Record NX, PIE, RELRO, canary, ASLR assumptions, interpreter, libc/loader hashes, and
  expected input framing.
- Run local samples under a short `timeout`; retain a compact crash/register summary.
- Keep the supplied loader and libc beside the working copy; do not infer their version
  from the host. Record one `/proc/<pid>/maps` snapshot only when it answers an address
  or mapping question.

## Primitive-driven plan

1. Reproduce the failure with the smallest input.
2. Determine whether the issue yields instruction-pointer control, an address leak, an
   arbitrary/limited write, or only a semantic bypass.
3. Account for each mitigation before choosing ROP, ret2libc, format-string, heap, or
   logic paths.
4. Make the exploit deterministic: explicit byte protocol, bounded reads, timeouts,
   architecture/endian assumptions, and clear local/remote switch.
5. Reject a path after the same primitive fails twice without new evidence.

Remote interaction must be narrow and allowlisted. Do not use shell access beyond what
the CTF service intentionally grants, and never pivot to adjacent hosts.

## Selective dynamic proof

- Set a temporary breakpoint at the suspected copy, formatter, allocator, or indirect
  call; use a watchpoint only for the specific value whose writer is unknown.
- Bound GDB recording before enabling it; retain the relevant instruction window, not a
  whole execution log.
- Treat an ASLR-, libc-, or loader-dependent observation as local-only until the exact
  supplied runtime reproduces it. Read the matching route in
  [archetypes.md](archetypes.md) for preconditions and verification.
