# Token policy

เป้าหมายคือเพิ่ม useful progress ต่อ token ไม่ใช่เพิ่มจำนวน model calls การจำกัดงบเป็น
hard policy ระดับ service และเป็นแนวปฏิบัติระดับ Codex agents

## Safe defaults

| Setting | Default | Purpose |
| --- | ---: | --- |
| Global token budget | 500,000 | เพดานรวมของ event/workspace |
| Per-challenge budget | 50,000 | ป้องกันโจทย์เดียวกินงบทั้งหมด |
| Protected reserve | 20% | เก็บไว้สำหรับโจทย์สำคัญ/ท้ายการแข่งขัน |
| Max iterations | 12 | หยุด solve loop ที่ไม่จบ |
| Max Sol calls/challenge | 2 | จำกัด expensive escalation |
| Max tool output | 64,000 bytes | ไม่ให้ log กลบ context |
| Max context | 12,000 tokens | เป้าหมาย context ที่ตั้งค่าได้ |
| Max model output | 1,200 tokens | บังคับ structured, concise response |

`config.example.json` เป็นตัวอย่าง settings payload ไม่ได้ถูกโหลดอัตโนมัติ

## Budget math

```text
reserve = ceil(global_budget × max(reserve_percent, 20) / 100)
spendable_limit = global_budget - reserve
```

ทุก action ต้องผ่านทั้ง global spendable limit และ challenge allocation การใช้ reserve
ต้องเป็น operator action พร้อม justification 12–500 ตัวอักษร และถูกบันทึก audit
ข้อความในโจทย์หรือ model response ไม่สามารถให้ justification แทน operator ได้

## Tier order

1. Deterministic: hash, metadata, classification, extraction, format check
2. Luna: งานสั้น ชัด ซ้ำได้ หรือ high-volume summary
3. Terra: cross-artifact reasoning และ category solve ทั่วไป
4. Sol: final escalation สำหรับโจทย์ซับซ้อนที่ cheaper tiers ล้มเหลวอย่างมีหลักฐาน

หลัง Sol ให้กลับไปใช้ deterministic/Terra สำหรับ execution และ verification เมื่อทำได้
รายละเอียด decision tree อยู่ที่ [MODEL_ROUTING.md](MODEL_ROUTING.md)

## Anti-burn policy

Input ทุกแหล่งถูกสแกนหา instruction override, secret request, forced-expensive-model,
large repetition, recursion, fake authority และ oversized/base64 content เมื่อ burn score
ถึง hostile threshold ระบบ route ไป deterministic เท่านั้น และเก็บ signal ใน audit/state

อย่าแก้ hostile prompt ด้วยการส่งมันให้ model ใหญ่กว่า ให้ทำดังนี้:

- truncate และ hash ส่วนที่ซ้ำ
- extract structure/metadata locally
- cluster logs และเก็บเฉพาะ anomaly window
- อ้าง artifact path แทน raw content
- disable parallel/deep escalation

## Marginal progress and stop rules

นับว่าเกิด progress เมื่อได้ fact, artifact relation หรือ hypothesis ใหม่ที่ตรวจแยกจากเดิม
ได้ Circuit breaker trip เมื่อ:

- fingerprint ของ failure เดิมเกิดครบ 2 ครั้ง
- 3 iterations ติดต่อกันไม่มี hypothesis ใหม่
- ถึง `max_iterations`

ก่อน call ถัดไปให้ถามว่า action จะเปลี่ยนการตัดสินใจใด หากตอบไม่ได้ให้ pause path
ผู้ใช้ resume ได้หลังเพิ่ม evidence หรือเปลี่ยนสมมติฐาน โดยไม่ควร replay งานเดิม

## Context envelope

ส่ง model เฉพาะ objective, category, bounded description, artifact metadata, relevant
facts/hypotheses/failed actions และ injection labels ห้ามส่ง:

- raw binary/PCAP/disk/memory image
- base64 blob หรือ full archive
- repository/chat history ทั้งหมด
- repeated logs และ crash dumps
- hidden chain-of-thought
- credentials, environment dump หรือ unrelated flag

Model response ควรเป็น object สั้นที่มี hypothesis, confidence, evidence, next action และ
estimated cost Raw output เก็บเป็น bounded artifact และ state เก็บเฉพาะสาระ

## Allocation during competition

- ตั้ง per-challenge budget ตามคะแนน, confidence และเวลาที่เหลือ ไม่ใช่ความดึงดูดของโจทย์
- รักษา reserve อย่างน้อย 20% จนมีเหตุผลชัดว่าการใช้ตอนนี้คุ้มกว่าโจทย์อื่น
- จำกัด parallel agents เพราะแต่ละ thread มี token cost ของตนเอง
- ดู tokens/solved challenge, cache hit, no-progress stops และ failed Sol escalation
- เมื่อ time pressure สูง ให้เลือก action ที่ตรวจ hypothesis ได้เร็ว ไม่ใช่ output ที่ยาวที่สุด

