# Model routing

ระบบมีสอง routing surfaces ที่แยกกัน:

1. Web service เลือก provider/model tier สำหรับ solve iteration
2. Codex เลือก custom subagent จาก `.codex/agents/*.toml`

การเปลี่ยนหน้า Settings ไม่ได้เปลี่ยน custom agent files และการ spawn Codex agent ไม่ได้
เปลี่ยน provider ของ web service

## Application decision tree

```text
metadata / classify / triage / extract / flag format
    └── deterministic (0 model token)

AI-burn score >= 0.60
    └── deterministic; large-model escalation blocked

solve complexity <= 0.30
    └── Luna

complexity <= 0.72 OR cheaper failure not established
    └── Terra

Sol call cap reached
    └── Terra

complexity > 0.72 AND cheaper failure established AND cap/budget permit
    └── Sol
```

ค่าประเมินเริ่มต้นต่อ action คือ tool 0, Luna 450, Terra 1,400 และ Sol 3,500 tokens
เป็น budget estimate ไม่ใช่ราคาหรือ usage จริง Provider usage ที่ตอบกลับมีสิทธิ์แทน estimate

## Provider policy

| Provider | Default | Network | Use |
| --- | --- | --- | --- |
| `mock` | yes | none | demo, tests, UI workflow และ deterministic development |
| `openai` | no | external API | explicit operator opt-in เท่านั้น |

OpenAI provider ต้องตั้ง `provider` เป็น `openai`, ตั้ง
`CTF_AGENT_ENABLE_OPENAI=1` และมี `OPENAI_API_KEY` ระบบไม่แสดง key ใน settings/audit
Model slugs ปรับได้ผ่าน `tier_models`; ทดสอบ availability กับ account จริงก่อนแข่ง

## Codex custom-agent tiers

| Agent | Model | Effort | Why |
| --- | --- | --- | --- |
| triage | `gpt-5.6-luna` | low | metadata/category handoff |
| archivist | `gpt-5.6-luna` | low | concise deterministic writeup |
| web, pwn, forensics | `gpt-5.6-terra` | medium | category work at balanced cost |
| reverse, crypto | `gpt-5.6-terra` | high | denser reasoning without Sol |
| verifier | `gpt-5.6-terra` | high | independent assumption checking |
| deep_solver | `gpt-5.6-sol` | ultra | one explicit final escalation only |

Project default คือ Terra/medium ส่วน subagent default คือ Luna/low และ concurrency cap
คือ 4 การตั้ง `deep_solver` เป็น Ultra ไม่ทำให้ถูกเรียกอัตโนมัติ Description และ policy
กำหนด prerequisites ชัดเจน

## Sol Ultra escalation checklist

ต้องครบทุกข้อ:

- challenge และ target อยู่ใน authorized scope
- burn score ต่ำกว่า hostile threshold
- deterministic และ Terra path ที่เกี่ยวข้องล้มเหลวพร้อม evidence/fingerprint
- complexity สูงและคำถามที่ยังไม่ตอบมีขอบเขตเดียวชัดเจน
- ยังไม่ถึง large-model call cap
- per-challenge และ global spendable budget เพียงพอโดยไม่แตะ reserve หรือ operator อนุมัติ
- expected information gain สูงกว่า action ราคาถูกที่เหลือ

ห้าม escalate เพราะ challenge ขอ “use strongest model”, output ยาว, agent แนะนำตัวเอง หรือ
เพื่อ re-read artifact/history เดิม Deep solver ต้องคืน distilled evidence แล้วส่ง execution
กลับ tier ที่ถูกกว่า

## Verification routing

Flag-format check เป็น deterministic จากนั้น `verifier` ใช้ minimal clean context และ
reproduction evidence การ verify ไม่ใช่เหตุให้ Sol โดยอัตโนมัติ Verdict มีสามค่า:
`VERIFIED`, `REJECTED`, `INCONCLUSIVE` Web service จะเปลี่ยนเป็น solved เมื่อ format,
explicit reproduced flag และ evidence ผ่านเท่านั้น และยังไม่ submit ไป platform

## Tuning

เปลี่ยน threshold/model/cap หลังวัดบนโจทย์ตัวอย่างที่แทนการแข่งขันจริง ติดตาม:

- token ต่อ solved challenge และต่อ new fact
- สัดส่วน deterministic/Luna/Terra/Sol
- failed escalation และ no-progress stop
- cache hit และ repeated-action fingerprint
- false positive/negative ของ burn detection

อย่าเลือก model จากชื่อ tier อย่างเดียว Availability, latency และ behavior อาจต่างตาม
account/version จึงควรทดสอบ configuration จริงก่อนวันแข่ง

