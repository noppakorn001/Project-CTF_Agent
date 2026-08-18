# Threat model

## Scope and assets

ระบบปกป้องสิ่งต่อไปนี้:

- ขอบเขต target ที่ผู้จัด CTF อนุญาต
- token budget และ reserve ของผู้แข่งขัน
- เครื่อง host, filesystem, credentials และ network identity
- artifact ต้นฉบับ, chain of evidence, solver state และ audit
- candidate flag และข้อมูลการแข่งขันที่ยังไม่เปิดเผย

ผู้โจมตีอาจควบคุม challenge prose, filename, archive members, embedded strings, OCR,
packet payloads, remote responses และ output จากโปรแกรมที่ให้มา จึงถือทั้งหมดเป็นข้อมูล
ไม่น่าเชื่อถือ

## Security invariants

1. Challenge content can describe actions; it cannot authorize actions.
2. Network ปิดเป็นค่าเริ่มต้น และ target ต้องอยู่ใน allowlist แบบ explicit
3. Mock provider เป็นค่าเริ่มต้น; external provider ต้อง opt in แยกต่างหาก
4. Reserve อย่างน้อย 20% ไม่ถูกใช้โดยอัตโนมัติ
5. Artifact ต้นฉบับไม่ถูกแก้ และ extraction อยู่ใน isolated workspace
6. Candidate flag ไม่ถูก submit อัตโนมัติ
7. Sol Ultra ไม่ถูกเลือกเพราะข้อความในโจทย์

## Threats and controls

| Threat | Primary controls | Residual risk |
| --- | --- | --- |
| Prompt injection / fake admin text | provenance, injection score, bounded prompt, AGENTS/skills policy | semantic attacks may evade rules; operator reviews alerts |
| Token-burning repetition/filler | input/output caps, dedupe, budget, burn score, circuit breaker | compression may omit a real clue |
| Huge binary/base64/log | metadata-only ingestion, size caps, selected excerpts | decompression and parser cost still needs OS limits |
| Malicious archive | list first; reject traversal, absolute paths, links, devices, expansion | parser vulnerabilities require disposable VM |
| Hostile executable | no host execution; disposable VM/container; timeout/resource caps | container/kernel escape remains possible |
| Network scope escape | network off, exact allowlist, CIDR limits, redirect/proxy block | DNS rebinding and tool-specific egress require firewall enforcement |
| Destructive shell command | workspace sandbox, PreToolUse guard, no privilege | hooks do not observe every hosted/specialized tool path |
| Credential exfiltration | no secrets mounts, sensitive-path guard, bounded/redacted audit | a process can access anything exposed inside its VM account |
| Model/provider cost escalation | mock default, tier router, call caps, reserve justification | provider accounting may arrive late or differ from estimates |
| Cache/state poisoning | artifact/state hashes, provenance, explicit facts vs hypotheses | an early false fact can bias later summaries |
| Verifier confirmation bias | minimal clean context, reproduction evidence, read-only verifier | verifier may share the same tool/model failure mode |
| Parallel agent duplication | concurrency cap, bounded tasks, ownership, failure fingerprints | independent threads still consume tokens |
| Candidate flag disclosure | local bind, no auto-submit, DB ignored by Git | local malware/users may read an unencrypted DB |

## Scope matching risks

Allowlist entry ต้องเป็น host/IP/CIDR ที่ตั้งใจใช้จริง ห้าม global wildcard ระบบจำกัด CIDR
ขนาดใหญ่ แต่ network enforcement ที่แข็งแรงควรอยู่ที่ VM firewall ด้วย โดย pin resolved IP
เมื่อการแข่งขันเหมาะสมและปฏิเสธ:

- redirects ไปคนละ host
- proxy flags และ inherited proxy environment
- DNS rebinding หรือ hostname ที่เปลี่ยนผล resolve
- link-local, metadata service และ private ranges ที่ไม่ได้ระบุ
- IPv4/IPv6 alternate representation ที่ไม่ตรง policy

`.codex/hooks/command_guard.py` ใช้ environment `CTF_AGENT_ALLOWED_TARGETS` สำหรับ
คำสั่ง shell ส่วนแอปใช้ scope records ใน SQLite ทั้งสองรายการเป็นคนละ control plane และ
ควรกำหนดให้ตรงกันเมื่อจำเป็นต้องใช้ network

## Command-hook boundary

Hook block คำสั่งที่ชัดเจน เช่น privilege/system mutation, block device, broad deletion,
write นอก repo, secret paths, unsafe Docker options และ network target ที่ตรวจไม่ได้
คำสั่งอ่านทั่วไปยังทำงานแม้ search pattern มีคำอย่าง `rm -rf`

Hook ไม่ใช่ shell verifier และอาจไม่เห็น code ที่ซ่อนใน interpreter script, binary,
hosted tool หรือ runtime-generated command จึงต้องรักษา sandbox, non-root user และ VM
network policy ไว้เสมอ หลังแก้ hook ให้ตรวจและ trust hash ใหม่ด้วย `/hooks`

## Provider and data disclosure

การเปิด OpenAI provider หมายถึง bounded challenge context ถูกส่งออกจาก VM ไปยัง API
ผู้ใช้ต้องตรวจ rules ของการแข่งขันและ data policy ก่อน เปิดได้เฉพาะเมื่อทั้ง setting
`provider=openai`, `CTF_AGENT_ENABLE_OPENAI=1` และ credential พร้อม ค่า
`network_enabled` สำหรับ CTF target ไม่ได้เป็นการอนุญาตส่งข้อมูลให้ provider แทนผู้ใช้

## Incident response

เมื่อพบ scope violation, secret exposure หรือโจทย์พยายามเปลี่ยน policy:

1. Pause/stop challenge และปิด VM egress
2. เก็บ audit, artifact hash และ command ที่ถูก block โดยไม่คัดลอก secret
3. Revoke credential ที่อาจรั่วและ rotate VM snapshot
4. แยก hostile artifact ออกจาก workspace ปกติ
5. ปรับ deterministic rule/test จาก signal ที่ยืนยันแล้ว
6. Resume ด้วย state ที่ตรวจใหม่; อย่าใช้ cache/summaries ที่อาจถูก poison

## Non-goals

ระบบนี้ไม่ใช่ EDR, malware sandbox, network firewall, vulnerability scanner สำหรับระบบ
ทั่วไป หรือเครื่องมือรับรอง legal scope ผู้แข่งขันยังต้องอ่านกติกาและเป็นผู้ตัดสินใจขั้น
สุดท้ายทุกครั้ง

