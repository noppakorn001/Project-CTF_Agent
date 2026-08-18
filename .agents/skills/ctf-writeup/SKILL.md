---
name: ctf-writeup
description: Produce a concise reproducible writeup after an authorized CTF solution has independent verification, and distill only broadly reusable lessons. Do not mark unverified candidates as solved.
---

# CTF Writeup

Read [template.md](references/template.md) and fill only sections supported by evidence.
Read [reusable-lessons.md](references/reusable-lessons.md) before proposing a lesson
for a shared category reference.

- Require the challenge objective, original artifact hashes, decisive evidence, solve
  script paths, candidate flag, and verifier verdict.
- Keep commands bounded and reproducible from a clean challenge workspace.
- Explain the decisive technique, not every exploratory transcript.
- Include failed approaches only when they prevent a likely repeated waste.
- Redact unrelated credentials, cookies, API keys, and personal data.
- Store a final flag only after `VERIFIED`; otherwise label it candidate/inconclusive.
- Add reusable knowledge to the existing category reference only when it generalizes.
  Use the lesson taxonomy to identify the supported playbook, a bounded bridge, or a
  challenge-specific outcome. Never create a new skill for one challenge or subtype.
- Never submit the flag or publish the writeup automatically.
