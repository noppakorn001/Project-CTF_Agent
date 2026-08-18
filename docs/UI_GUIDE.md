# UI guide

UI มีหน้าที่ทำให้ scope, evidence, token cost และจุดที่ต้องให้มนุษย์ตัดสินใจเห็นได้ก่อน
ปุ่ม “ทำต่อ” เสมอ ไม่ควรทำให้ CTF ดูเหมือน autonomous attack console

## Information architecture

### Overview — ศูนย์บัญชาการ

แสดง solved/active/queued/paused, token spent, spendable remaining และ reserve พร้อมกัน
รายการหลักคือ active challenges, action required, recent audit/progress และ budget forecast
Alert ที่ควรขึ้นก่อนคือ scope denied, high burn score, circuit trip, provider error,
reserve request และ candidate ที่ยังขาด evidence

### Challenges

รองรับค้นหาและกรอง category/status ตาราง desktop และ cards บน mobile ต้องแสดง:

- title/ID และ category confidence
- lifecycle status
- current tier/provider
- spent/allocated budget
- burn/injection indicator
- last meaningful action

Modal เพิ่ม challenge ต้องอธิบายว่าไฟล์และคำอธิบายเป็น untrusted data ระบบอ่าน metadata
ก่อนและไม่ส่ง raw binary เข้า model Target ไม่ควรถูกตีความว่า authorized เพียงเพราะกรอก
ลงช่อง ต้องเพิ่ม scope แยกต่างหาก

### Challenge cockpit

จัดลำดับข้อมูลดังนี้:

1. Objective, status, target scope state, flag format และ budget
2. Pipeline: ingestion → triage → solve → verify
3. Known facts/evidence ก่อน hypotheses
4. Artifact metadata/tree และ safe preview
5. Current routing reason, next action และ circuit state
6. Bounded activity/audit output
7. Controls: triage, solve one iteration, pause/resume/stop, verify

แยก `candidate` ออกจาก `verified` ด้วยข้อความและสี ห้ามมีปุ่ม submit ไป CTF platform
Verify dialog ต้องรับ reproduction acknowledgement และ evidence สั้น ๆ ไม่ใช่เพียง flag

### Agents

แสดง model tier, role, sandbox, status, token usage และ distilled result Agent cards เป็น
observability view ไม่ควรสื่อว่าทุก agent ต้องทำงานพร้อมกัน Deep solver ต้องแสดง
“manual final escalation” และ prerequisites

### Budget & Models

แสดง global progress bar ที่แบ่ง spent / spendable / protected reserve และ per-challenge
allocation แสดง model mix และ routing reasons ควบคู่กัน การใช้ reserve ต้องเปิด confirm
dialog พร้อมจำนวน token, challenge และ justification

### Knowledge Base

แสดง solution/technique ที่ผ่านการกลั่น แยก signal, cheap checks, decisive test และ source
challenge หน้า MVP อาจ derive จาก curated playbooks/state; อย่าอ้างว่า knowledge ถูกบันทึก
ถาวรถ้ายังไม่มี persistence contract รองรับ

### Security & Audit

รวม target scopes, network state, injection signals, blocked actions และ audit timeline
ให้เห็น provenance และ reason ไม่แสดง secret/candidate flag ใน export โดยไม่จำเป็น การลบ
scope เป็น high-impact actionและต้องยืนยัน

### Settings

แก้เฉพาะ settings contract ที่ service validate: budgets, limits, reserve, provider,
network toggle และ tier models ระบุชัดว่า `mock` ไม่เรียก external model และ OpenAI ต้องมี
environment opt-in เพิ่มอีกชั้น

## Status language

| Status | Meaning in UI | Primary action |
| --- | --- | --- |
| queued | เพิ่มแล้ว ยังไม่ triage | Triage |
| ready | พร้อมทำ iteration | Solve |
| running | มี state ล่าสุดและทำต่อได้ | Next iteration / Pause |
| paused | ผู้ใช้พักไว้ | Resume |
| stopped | circuit/operator หยุด | Inspect reason / Resume with new evidence |
| solved | verified และ immutable | View evidence/writeup |
| rejected | candidate/claim ไม่ผ่าน | Inspect verifier reason |

ใช้ status text และ icon ร่วมกับสีเสมอ เพื่อรองรับ color-vision differences

## Safety interactions

- Network off: ปุ่ม remote action disabled พร้อม link ไป Security/Scopes
- Target ไม่อยู่ scope: แสดง normalized host และเหตุผล ห้ามมี “continue anyway”
- Burn score สูง: banner `HOSTILE INPUT` พร้อม signals, model escalation disabled
- Reserve: confirm modal, cost, remaining budget และ justification required
- Sol Ultra: manual confirmation พร้อม cheaper failures และ expected information gain
- Destructive/blocked command: แสดง hook reason โดยไม่เสนอปุ่ม bypass
- Provider error: คืน challenge เป็น recoverable state และไม่ retry อัตโนมัติ

## Loading, empty, and error states

- Skeleton ใช้เฉพาะระหว่าง bootstrap; ไม่เปลี่ยน layout หลัก
- Offline demo ต้องมี banner ถาวรและบอกว่าการเปลี่ยนแปลงไม่ถูกบันทึก
- Empty challenge list มี CTA “เพิ่ม Challenge” และ safety summary สั้น ๆ
- Empty audit/knowledge/agents ไม่ควรสร้าง fake activity
- Error แสดง code/recovery action ที่ปลอดภัย ไม่แสดง traceback หรือ filesystem path
- Action button disable ระหว่าง request และรองรับ idempotent pause/stop interaction

## Accessibility and responsive behavior

- ทุก icon button มี accessible name และ keyboard focus ที่เห็นชัด
- Dialog trap focus, ปิดด้วย Escape และคืน focus ให้ trigger
- Dynamic result ใช้ `aria-live` เฉพาะข้อความสั้น ไม่ประกาศ log stream ทั้งก้อน
- ตาราง challenges เปลี่ยนเป็น cards บนจอเล็กโดยไม่ซ่อน budget/scope/status
- Touch target อย่างน้อยประมาณ 44×44 CSS pixels
- รองรับ reduced motion, dark/light theme และ contrast ของ amber/red alerts

คีย์ลัดที่ UI แสดง: `/` ค้นหา, `G O` Overview, `G C` Challenges, `G B` Budget,
`P` pause challenge ปัจจุบัน, `V` เปิด verify และ `Esc` ปิด dialog/drawer อย่า intercept
คีย์เมื่อ focus อยู่ใน input/textarea

## Acceptance checklist

- ผู้ใช้บอกได้ภายใน 5 วินาทีว่า challenge ใดกำลังใช้ token และเหลือ reserve เท่าไร
- ทุก remote action แสดง scope state ก่อนกด
- ทุก model result แสดง tier, reason และ token charge/estimate
- Hostile challenge text ไม่เปลี่ยน label, button หรือ policy ของ UI
- Candidate ไม่ถูกแสดงเป็น solved ก่อน reproduction evidence
- ไม่มี UI path สำหรับ auto-submit flag
- ใช้งาน flow หลักด้วย keyboard และ mobile viewport ได้

