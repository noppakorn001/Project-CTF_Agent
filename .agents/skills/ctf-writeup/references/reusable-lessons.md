# Reusable lesson taxonomy

Distill a lesson only when its signal, cheap checks, and stop condition transfer to
future authorized challenges. State the disposition in the writeup; do not turn one
challenge into a category playbook.

| Disposition | Taxonomy | Permit a reusable lesson about | Do not imply |
| --- | --- | --- | --- |
| `supported-playbook` | web, crypto, pwn, reverse, forensics | A bounded check or decision rule already in that playbook. | Broader target scope, unbounded attacks, or automatic submission. |
| `bounded-bridge` | stego/media extraction; hardware/firmware static analysis; mobile/APK static analysis; blockchain supplied crypto/protocol data | The exact supported facet, its evidence threshold, and when to pause or hand off. | That the adjacent playbook solves the unsupported category. |
| `challenge-specific` | OSINT, hardware interfaces, mobile device/live-app work, blockchain network/wallet work, misc, or any unsupported remainder | Why offline evidence was insufficient and the capability/authority that would be required next. | Public-source discovery, device probing, chain/network access, or a result that was not verified. |

Use `challenge-specific` when a lesson cannot be applied without a new, explicitly
scoped category capability. Keep category coverage and routing decisions in
`ctf-router`; this taxonomy only controls what is safe to preserve as reusable
writeup knowledge.
