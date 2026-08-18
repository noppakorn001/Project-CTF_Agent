---
name: ctf-reverse
description: Reverse engineer supplied authorized CTF executables, bytecode, APKs, custom VMs, or firmware through targeted static analysis and isolated dynamic checks. Use bounded emulation for interpreters and static-first checks for obfuscation; do not execute unknown artifacts on the host.
---

# CTF Reverse

Read [playbook.md](references/playbook.md) before dynamic analysis. Then read only the
matching route in [archetypes.md](references/archetypes.md).

- Preserve artifact hashes and analyze a working copy in a disposable environment.
- Start with format, sections, imports, symbols, resources, and bounded strings.
- Trace from input to comparison/output; name only functions supported by evidence.
- Prefer extracting constraints or reimplementing a small routine over patching blindly.
- If dynamic work is needed, use a timeout, controlled input, and no network.
- Store harnesses, patches, and solve scripts in the challenge workspace.
- Avoid full disassembly/decompiler dumps, repeated rescans, and unsupported guesses.
- Send any recovered flag to the verifier; never auto-submit it.
