# Reverse archetypes

Choose the narrowest format or behavior route. Preserve the original and perform dynamic
work only in a disposable, network-disabled environment. A decoded-looking string is a
lead until it satisfies the decisive check.

## Native comparison or reversible transform

| Item | Route |
| --- | --- |
| Evidence | Input reaches a compare, branch, checksum, table lookup, or short transform before success output. |
| Cheapest proof | Extract the exact constants and reimplement only the transform/compare in a small local script; test known failure and success-path conditions. |
| Preconditions | Establish bytes versus text, length/NUL handling, signedness, endianness, and any initialization state. Use ELF segments and relocations, not decompiler names alone, for native addresses. |
| Stop | Stop when the proposed input never reaches the decisive branch, two independent translations disagree, or an unresolved external value controls the result. |
| Verify | Run the script and original under the same controlled input; record the artifact hash and matching branch/output. |

## Constraint or state-machine checker

| Item | Route |
| --- | --- |
| Evidence | Many branches accumulate relations over input bytes, indexes, or states; success follows a final aggregate condition. |
| Cheapest proof | Write compact pseudocode and enumerate only deterministic constraints/state transitions; validate each against an observed branch. |
| Preconditions | Establish input length, character domain, arithmetic width/overflow, initial state, and whether constraints are independent. Use a solver only after this model is complete and bounded. |
| Stop | Stop if constraints are inconsistent with the binary trace, search space lacks a stated bound, or two refinements add no constraint. |
| Verify | Evaluate the recovered candidate against every extracted constraint and replay it in the artifact. |

## Packed, compressed, or self-modifying native code

| Item | Route |
| --- | --- |
| Evidence | Unusual section permissions/entropy, a small unpacking stub, runtime writes into executable memory, or imports resolved after startup. |
| Cheapest proof | Identify the transition from loader/stub to derived code; capture only the mapped derived range after the transition and hash it. |
| Preconditions | Preserve architecture, loader, memory-map permissions, and any key/environment input. Dynamic capture belongs in the isolated CTF VM only. |
| Stop | Stop if no executable derived region appears, capture varies without an explained key/ASLR basis, or the suspected packer boundary is unsupported by a trace. |
| Verify | Reproduce the boundary and derived hash from a fresh process before analyzing the result as a new artifact. |

## Android APK, DEX, and JNI boundary

| Item | Route |
| --- | --- |
| Evidence | An APK contains `classes*.dex`, manifest/resources, or native libraries; Java/Kotlin code passes a candidate to `native` methods or loads a library. |
| Cheapest proof | Inventory ZIP members and DEX method/string references, then trace one argument across the managed/native boundary to the comparison. |
| Preconditions | Record APK and DEX hashes, ABI-specific `.so` path, manifest entry component, DEX version, and device/API assumptions. Never install or run an untrusted APK on the host. |
| Stop | Stop when the selected method has no path to a success condition, the native library is for another ABI, or two call-site traces contradict the argument mapping. |
| Verify | Reproduce the argument/value mapping with a static cross-reference or isolated trace and test the exact check locally. |

## JVM class or JAR bytecode

| Item | Route |
| --- | --- |
| Evidence | `CAFEBABE` class files, JAR members, constant-pool strings, or bytecode methods reach the check. |
| Cheapest proof | Inspect the class-file version, constant pool, method `Code` attribute, and invoked methods; translate only the checker method's operand-stack behavior. |
| Preconditions | Respect big-endian class-file fields, constant-pool indices, descriptor types, class-loading/resource assumptions, and bytecode verification. Do not equate decompiler output with the actual operand stack. |
| Stop | Stop if the class version/runtime cannot load, the candidate path is unreachable, or the translated stack effects fail a trace. |
| Verify | Compare the translated method result against the class under a controlled local runtime, with the input and class hash recorded. |

## WebAssembly module

| Item | Route |
| --- | --- |
| Evidence | `\0asm` magic, declared sections, exported functions, linear-memory accesses, or host imports mediate input/checking. |
| Cheapest proof | Parse section order, exports, imports, data segments, and the smallest exported/checker function; emulate or invoke it with a bounded local harness. |
| Preconditions | Establish module version, host import behavior, memory limits, byte offsets, and integer widths. Host glue may own decoding or success display, so trace both sides. |
| Stop | Stop when the required import has no local deterministic substitute, the function is not reachable from exports/glue, or two parses disagree on section boundaries. |
| Verify | Re-run the harness with fixed imports and input; confirm the same return/memory effect and module hash. |

## Firmware image or opaque container

| Item | Route |
| --- | --- |
| Evidence | Header/magic, partition table, embedded filesystem, architecture strings, or a boot/application entry region identify a container rather than a single executable. |
| Cheapest proof | Parse declared offsets and sizes, validate non-overlap/bounds, and extract only a targeted member into a new workspace path for separate classification. |
| Preconditions | Reject traversal-like names, symlinks, device files, and implausible expansion sizes. Record CPU/endian/load-address evidence before disassembling. |
| Stop | Stop if offsets exceed the artifact, members overlap without a documented format reason, or extraction lacks provenance. |
| Verify | Recompute member hashes and offsets from the original, then reproduce the selected member's classification. |

## Custom VM, bytecode, or opcode interpreter

| Item | Route |
| --- | --- |
| Evidence | A dispatch loop, opcode table, bounded bytecode buffer, or host API executes supplied instructions. |
| Cheapest proof | Extract opcode widths, registers/stack, memory bounds, and halt/check instructions; emulate only the shortest supplied input. |
| Preconditions | Establish version/format, endianness, integer width, input cap, and host imports. Do not execute an untrusted VM outside the disposable environment. |
| Stop | Stop when opcode boundaries are ambiguous, input length is unbounded, or two traces disagree. |
| Verify | Compare the emulator trace, final state, and return value with a clean artifact run and record the bytecode hash. |

## Anti-analysis or obfuscation layer

| Item | Route |
| --- | --- |
| Evidence | Opaque predicates, encrypted strings, anti-debug checks, control-flow flattening, or environment-dependent branches obscure a known check. |
| Cheapest proof | Identify one predicate/string decode and show its effect on the checker in a static copy; patch only an isolated copy if a trace requires it. |
| Preconditions | Preserve original hash, architecture, loader, and environment assumptions. Do not disable host security controls or use external telemetry. |
| Stop | Stop after two failed decode/trace hypotheses or when the path depends on unavailable environment state. |
| Verify | Re-run the original and isolated copy with the same fixed input/environment and match the decoded bytes or branch trace. |

## Primary references

- [ELF format (Linux `elf(5)`)](https://man7.org/linux/man-pages/man5/elf.5.html), [GDB breakpoints/watchpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints.html), and [Ghidra Debugger course](https://ghidra.re/ghidra_docs/GhidraClass/Debugger/README.html)
- [Android DEX format](https://source.android.com/docs/core/runtime/dex-format) and [Android JNI tips](https://developer.android.com/training/articles/perf-jni)
- [JVM class-file format](https://docs.oracle.com/en/java/javase/26/docs/specs/jvms/jvms-4.html) and [JVM instruction set](https://docs.oracle.com/en/java/javase/26/docs/specs/jvms/jvms-6.html)
- [WebAssembly core binary format](https://webassembly.github.io/spec/core/binary/index.html)
- [Ghidra Debugger course](https://ghidra.re/ghidra_docs/GhidraClass/Debugger/README.html): controlled trace/static correlation for supplied binaries.
