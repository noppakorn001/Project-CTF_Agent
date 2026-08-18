# Easy1 — Base32 → marker removal → Base64

**Status:** `RESEARCH_ONLY`

ตรวจ alphabet/padding ให้ตรง Base32 ก่อน decode. หลังได้ bytes ให้แยก marker ที่ source
กำหนดอย่างชัดเจน แล้วตรวจว่า payload ที่เหลือเป็น Base64 ก่อน decode รอบถัดไป.

```python
import base64
outer = base64.b32decode(text.strip(), casefold=True)
inner = outer.strip().strip(b"/")
plain = base64.b64decode(inner, validate=True)
```

เก็บแต่ละ intermediate hash; ถ้า padding ไม่ตรงให้หยุดและตรวจ artifact แทนการเติม `=` แบบ
ไม่จำกัด.
