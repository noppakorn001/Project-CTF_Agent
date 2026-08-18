# Custom Protocol v2 — specification-led reassembly

**Status:** `RESEARCH_ONLY`

ค้น magic `STH` และ version 2 ด้วย display filter จากบทความ/สเปค แล้ว parse header,
sequence, length และ payload ตาม field widths ใน spec. เรียงชิ้นตาม sequence และตรวจ
checksum/declared length ก่อน decode.

```text
pcap → selected UDP frames → header validation → sequence map → length/checksum
→ bounded payload join → challenge-specific decode → independent replay
```

อย่าเดา endian/order จากข้อความที่อ่านได้เพียงบางส่วน; ถ้า field validation ไม่ผ่านให้เก็บ
เป็น inconclusive.
