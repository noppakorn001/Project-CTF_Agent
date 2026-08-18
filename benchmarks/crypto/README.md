# Blind competitive crypto benchmark

This is the implementation of the attached autonomous benchmark specification.
It is bookkeeping and blind-payload infrastructure only; it does not download
challenge data, search write-ups, execute arbitrary solvers, open sockets, or
submit flags.

## Populate a dataset

For each opaque ID, keep files in a workspace outside the solver's metadata
view:

```text
benchmarks/crypto/dataset/crypto_001/
  description.txt
  artifacts/
```

Add a manifest entry with `id`, `tier`, relative `description`,
`artifacts_dir`, optional `flag_format`, and an authorized `remote` object only
when the exact endpoint is approved. Do not put author, year, points, rating,
challenge name, solution, or write-up text in the blind payload. Preserve the
original files and record hashes externally in the operator notes.

The primary manifest must contain exactly 30 entries: 10 intermediate, 10
advanced, and 10 expert. It must not include picoCTF or solution-derived data.

## Validate and expose a blind payload

```bash
python3 -m ctf_agent benchmark validate \
  --manifest benchmarks/crypto/manifest.json \
  --root benchmarks/crypto/dataset --complete

python3 -m ctf_agent benchmark payload \
  --manifest benchmarks/crypto/manifest.json \
  --root benchmarks/crypto/dataset --id crypto_001
```

The payload contains only an opaque ID, description, artifact IDs/sizes/hashes,
the optional flag format, and the explicitly authorized host/port. Tier and
source metadata stay out of it.

## Record results and render the report

Copy the schema of `results.example.jsonl` into a result file. Each challenge
must have a terminal state from `SOLVED_CONFIRMED`, `SOLVED_UNCONFIRMED`,
`PARTIAL`, `FAILED`, `TIMEOUT`, or `CONTAMINATED`. A confirmed result needs
cryptographic consistency and clean replay evidence; a flag-shaped string is
not enough.

```bash
python3 -m ctf_agent benchmark report \
  --manifest benchmarks/crypto/manifest.json \
  --root benchmarks/crypto/dataset \
  --results benchmarks/crypto/results.jsonl \
  --output benchmarks/crypto/BENCHMARK_REPORT.md
```

The aggregator excludes contaminated records from primary solve statistics and
computes solve rate, median/P90 time, token/tool costs, failed hypotheses,
timeouts, human intervention, technique distribution, confidence, and the
conservative readiness level defined by the specification.

## Knowledge retention

Store generalized lessons—not flags or target secrets—in `knowledge/crypto/`.
Challenge-specific reproducible solvers belong under `solutions/<challenge_id>/`
or the challenge workspace, with a transcript and independent verifier.
