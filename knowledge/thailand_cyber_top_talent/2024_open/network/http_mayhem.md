# HTTP Mayhem — image LSB after object export

**Status:** `RESEARCH_ONLY`

หลัง export HTTP object ให้ยืนยัน PNG/JPEG signature และ dimensions. ถ้า source code ระบุ
red-channel LSB ให้ extract เฉพาะ channel นั้นตาม row-major order, group 8 bits และหยุดที่
NUL/expected length.

```python
bits = [(pixel[0] & 1) for pixel in pixels]
raw = bytes(sum(bit << (7-j) for j, bit in enumerate(bits[i:i+8]))
            for i in range(0, len(bits)-7, 8))
```

ภาพที่แก้/derived ต้อง hash แยก; ไม่ execute code ที่ถูก export มาจาก PCAP.
