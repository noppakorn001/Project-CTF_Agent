# Solution template

```markdown
# <challenge title>

- Challenge ID: `<id>`
- Category: `<category>`
- Status: `VERIFIED | REJECTED | INCONCLUSIVE`
- Original artifacts: `<path> — <sha256>`
- Authorized target: `<allowlisted target or offline>`

## Objective

<One sentence, including expected flag format when known.>

## Decisive evidence

<Minimal facts that establish the solution; cite artifact/output paths.>

## Reproduction

1. <Bounded command or script invocation>
2. <Expected compact result>
3. <Independent verification step>

## Result

Candidate: `<redact if the destination should not store flags>`

Verifier verdict: `<verdict and short reason>`

## Avoided dead ends

<Only repeated or high-cost paths worth remembering.>

## Reusable lesson

- Disposition: `supported-playbook | bounded-bridge | challenge-specific`
- Taxonomy: `<category/facet from reusable-lessons.md>`
- Lesson: <Signal → cheap checks → decisive test, or “challenge-specific; not distilled”.>
```

Do not paste huge logs, binary data, hidden chain-of-thought, or secrets. Link to bounded
artifacts and scripts instead.
