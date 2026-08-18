# Easy2 — hex then reverse

**Status:** `RESEARCH_ONLY`

ยืนยันว่า input มีแต่ hex และจำนวนอักขระเป็นเลขคู่, decode เป็น bytes, แล้วค่อย reverse
ตาม clue เรื่องลำดับ. ตรวจ flag prefix หลัง transform และเก็บ raw/intermediate hash.

```python
raw = bytes.fromhex(text.strip())
candidate = raw[::-1]
```
