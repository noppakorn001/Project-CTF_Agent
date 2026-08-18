# xfil — DNS hex reassembly

**Status:** `RESEARCH_ONLY`

สัญญาณคือ DNS query จำนวนมากที่ subdomain เป็น hex chunk และมี suffix คงที่. ดึงเฉพาะ
query จาก client ที่โจทย์ระบุ, normalize lowercase, ตรวจ label length/hex และเรียงตาม
frame number ก่อนเขียน derived file.

```bash
tshark -r xfil.pcapng -Y 'dns && dns.qry.name' -T fields \
  -e frame.number -e ip.src -e dns.qry.name
```

อย่าตัด suffix ด้วย `replace()` แบบไม่ตรวจ domain เพราะอาจเปลี่ยนข้อมูลจริง; ใช้ parser
ที่ยืนยันว่า query ลงท้ายด้วย exact suffix และรับเพียง label ที่อยู่ใน allowlist. หลังต่อ
bytes ให้ตรวจ file signature และ hash; ถ้าเป็นภาพให้ inspect แบบ offline เท่านั้น.
