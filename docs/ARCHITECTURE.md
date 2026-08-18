# Architecture

CTF Agent เป็น local-first orchestration console สำหรับ CTF ที่ได้รับอนุญาต เป้าหมาย
คือเก็บ policy, state, budget และหลักฐานไว้ในระบบเดียว โดยเริ่มจาก deterministic work
และไม่ผูกการใช้งานกับ model provider ใดเป็นค่าเริ่มต้น

## System map

```text
Browser UI
    │  same-origin JSON
    ▼
stdlib HTTP server ── request cap / safe static serving
    │
    ▼
CTFService ─────────── lifecycle / scope / budget / audit
    │
    ├── deterministic core
    │     metadata · bounded preprocessors · crypto fixture solvers · injection score · classifier · router · circuit breaker
    │
    ├── model provider interface
    │     mock (default) · optional OpenAI Responses API
    │
    └── SQLite repository
          challenges · artifacts · settings · scopes · cache · audit

Optional operator workflow in Codex
    ├── AGENTS.md policy
    ├── .agents/skills category playbooks
    ├── .codex/agents specialized subagents
    └── PreToolUse command guard
```

Codex custom agents กับ web application เป็นคนละ integration boundary: ไฟล์ใต้
`.codex/` และ `.agents/` ช่วย Codex ที่เปิดใน repository นี้ ส่วน `provider` ในหน้าเว็บ
ควบคุม model call ของ service โดยตรง แอปไม่ได้ spawn custom Codex agents อัตโนมัติ

## Runtime layers

### UI

หน้าเว็บเป็น static assets ที่ server เดียวกันให้บริการ จึงไม่ต้องมี frontend build step
ข้อมูลเริ่มต้นมาจาก bootstrap contract:

```text
app · stats · challenges · scopes · settings · audit
```

หน้า Agents และ Knowledge เป็นมุมมองที่กลั่นจาก challenge state, audit และ playbooks
ไม่ใช่ authority เพิ่มเติมเหนือ state ของ service

### HTTP boundary

`ctf_agent.http` ให้ JSON API และ static files ด้วย Python standard library โดยจำกัด
request body, ตรวจ content type, normalize static paths และไม่ส่ง exception/local path
กลับไปยัง client แอป bind ที่ `127.0.0.1` เป็นค่าเริ่มต้น

### Service boundary

`CTFService` เป็น application policy boundary สำหรับ:

- challenge ingestion, bounded artifact metadata และ cached read-only preprocessing
- status transitions
- scope authorization
- budget/reserve authorization
- deterministic triage และ model routing
- candidate verification
- audit events

HTTP handler ไม่ควรข้าม service ไปแก้ฐานข้อมูลโดยตรง

### Deterministic core

Core ไม่มี network และไม่มี model dependency ประกอบด้วย bounded artifact preprocessing
(text/binary signals, ZIP preflight, PNG structure/trailing bytes, ELF header),
prompt-injection scoring, artifact classification, scope matching, budget math, tier
routing, settings validation และ circuit breaker ฟังก์ชันเหล่านี้ควรถูกใช้ก่อน model
provider เสมอ Raw artifact bytes ไม่ออกจาก service boundary และ preprocessor ไม่เขียนหรือ
execute challenge data.

Crypto fixture solvers ใช้เฉพาะ prerequisite ที่ตรวจได้จาก input (`RSA` exact low root,
shared-factor GCD และ single-byte XOR) พร้อม cap และ relation replay ก่อนเสนอ candidate.
เส้นทาง pwn/reverse แบบ dynamic ยังต้องผ่าน isolated runner ตาม
[SANDBOX_EXECUTION.md](SANDBOX_EXECUTION.md); service ไม่ execute binary ที่ import เข้ามา
บน host.

### Provider boundary

`ModelProvider` รับ bounded prompt และคืน structured content พร้อม token accounting:

- `mock` เป็นค่าเริ่มต้น ปลอด network และให้ผล deterministic สำหรับ demo/test
- `openai` เป็น opt-in สองชั้น: เปลี่ยน setting และตั้ง environment gate/key

Provider ไม่มีสิทธิ์ขยาย scope, เปิด network สำหรับ challenge หรือใช้ reserve เอง
การเลือก model เป็นหน้าที่ของ router ก่อนเรียก provider

### Persistence

SQLite เก็บ settings, scopes, challenges, artifact bytes, cache และ audit ใน local DB
connection ถูกป้องกันสำหรับ threaded server และใช้ WAL เมื่อเป็นไฟล์จริง ไฟล์ฐานข้อมูล
เป็นข้อมูลอ่อนไหวเพราะอาจมี artifact และ candidate flag จึงถูก ignore จาก Git

## Challenge lifecycle

```text
queued ──triage──> ready ──solve──> running ──verify──> solved
   │                 │                │                 ▲
   └────pause────────┴────pause───────┘                 │
                       ▼                                │
                     paused ──resume──> ready            │
                       │                                 │
                       └────stop──────> stopped ─resume──┘

invalid candidate ──> rejected verification result, challenge returns ready
```

`solved` เป็น immutable terminal state ใน service และต้องมี format match พร้อม replay
แบบ bounded ของ deterministic evidence ต่อ bytes ต้นฉบับจาก artifact. คำอ้างว่า
reproduced/evidence จาก client ถูกเก็บเพื่อ audit แต่ไม่ใช่ independent verification และ
ไม่เพียงพอให้ solved. ระบบไม่ส่ง flag ไป platform

## Solve iteration

1. ปฏิเสธ terminal/paused state และ circuit ที่ trip แล้ว
2. ทำ deterministic triage/preprocessing หากยังไม่มี cache/state ที่เกี่ยวข้อง
3. ใช้ candidate ที่มี source locator เดียวก่อน model และเตรียม replay verification
4. ประเมิน complexity แบบ bounded หรือรับค่า operator ที่ validate แล้ว
5. route ไป tool/Luna/Terra/Sol ตาม burn score, cheaper failure และ large-call cap
6. ตรวจ per-challenge budget, global budget และ reserve
7. ตรวจ network policy เมื่อ operator ขอ remote path
8. ใช้ deterministic result หรือ provider ที่กำหนด แล้วเก็บเฉพาะ hypothesis ใหม่
9. update circuit breaker และ audit

ทุก iteration สร้าง hypothesis เดียวเพื่อให้ตรวจ marginal progress และหยุดงานซ้ำได้

## Trust boundaries

```text
Operator policy / local configuration       highest authority
Application and repository policy
Model response and bounded tool output
Challenge description / files / OCR         lowest authority
```

Challenge data ไม่สามารถเปิด network, เพิ่ม scope, ใช้ reserve, เลือก Sol, อ่าน secrets
หรือ submit flag ได้ ดูรายละเอียดที่ [THREAT_MODEL.md](THREAT_MODEL.md)

## Concurrency

- HTTP server รองรับหลาย request แต่ state mutations ผ่าน database lock/transactions
- Codex config จำกัด subagent พร้อมกันไม่เกิน 4 threads นอกเหนือจาก main thread
- งาน write-heavy ไม่ควรทำพร้อมกันใน challenge เดียว; parent agent ต้องกำหนด ownership
- Parallel agents มีค่า token แยก จึงใช้เฉพาะ hypothesis ที่เป็นอิสระและคุ้มค่า

## Deployment baseline

ใช้ disposable VM ที่ไม่มี personal data หรือ long-lived credentials, รันเป็น non-root,
bind UI ที่ loopback, จำกัด CPU/memory/disk/process และ snapshot/reset ได้ Network ของ VM
ควรปิดจนกว่าจะเพิ่ม target เฉพาะรายการ Command hook และ container เป็น defense in depth
ไม่ใช่ security boundary ที่สมบูรณ์
