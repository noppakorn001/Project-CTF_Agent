# Reverse challenge playbook

## Static narrowing

1. Record hash, file type, architecture, interpreter/runtime, packer indicators, and
   signatures.
2. Inspect entry points, imports, exports, sections, resources, and only relevant
   strings/cross-references.
3. Locate input acquisition, transforms, branch conditions, and success output.
4. Express the check as compact pseudocode with unresolved values marked explicitly.

Use the artifact format as a boundary: inspect its declared tables and metadata before
trusting a decompiler's recovered names or types. If a file embeds another runtime
(native JNI, bytecode, or a virtual machine), trace the value into the layer that makes
the decisive comparison.

## Choose the cheapest proof

- Direct comparison or reversible transform: implement a small decoder and test it.
- Constraint-heavy branch: extract constraints before considering a solver.
- Packed/self-modifying code: prove the packer boundary, unpack in isolation, then hash
  the derived artifact.
- Anti-debug or environment check: identify its exact effect; do not patch unrelated
  control flow.
- Native/managed boundary: inspect the layer that owns the decisive comparison rather
  than decompiling every dependency.

Dynamic traces are evidence only when the input, environment, artifact hash, breakpoint,
and observed value are reproducible. Stop after two unchanged failed approaches.
Use [archetypes.md](archetypes.md) only for the matched format or behavior; do not load
every route by default.
