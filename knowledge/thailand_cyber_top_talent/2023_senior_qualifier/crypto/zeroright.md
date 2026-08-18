# ZeroRight — unknown binary/text encoding

**Status:** `RESEARCH_ONLY`

อินพุตเป็น text ที่ประกอบด้วย `0`/`1`. ตรวจ whitespace, bit length, byte alignment และ
known flag prefix ก่อนเลือก transform. ทดลองเฉพาะ chain ที่มีเหตุผล เช่น group-by-8,
reverse byte order, XOR constant ที่มาจาก source; ไม่ใช้ “Magic” แบบไม่บันทึก candidate set.

```python
bits = "".join(line.strip() for line in open("ZeroRight.txt"))
assert set(bits) <= {"0", "1"}
assert len(bits) % 8 == 0
raw = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
print(raw[:256])
```

ทุก transform ต้องเก็บชื่อ, parameters, output hash และ verifier ที่ตรวจ expected format.
