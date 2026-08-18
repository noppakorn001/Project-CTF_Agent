# Whispers in the Wire — zlib stream in PCAP

**Status:** `RESEARCH_ONLY`

บทความชี้ว่าข้อมูลใน PCAP อาจเป็น compressed stream. ขั้นตอนที่ปลอดภัยคือสรุป flows,
เลือก stream ที่สัมพันธ์กับ challenge, ค้น zlib headers แบบ bounded และใช้ `zlib.decompress`
กับ slice ที่มี cap; ห้ามส่ง PCAP ทั้งก้อนไปโมเดล.

```python
import zlib
for magic in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
    # enumerate offsets in a bounded selected stream, not the whole host
    ...
```

ยืนยันด้วย decompressed length, printable ratio/flag format และ source frame offset.
