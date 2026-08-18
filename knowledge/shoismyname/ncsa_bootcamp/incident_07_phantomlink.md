# Incident 07-PhantomLink — TCP stream triage

**Status:** `RESEARCH_ONLY`

ใช้ protocol hierarchy แล้วไล่ `tcp.stream` ที่มีจำนวน packet/bytes ต่ำก่อน. อ่าน ASCII
เฉพาะ stream ที่มี marker จากโจทย์, ตรวจว่า payload เป็น Base64/ข้อความตาม alphabet และ
รวม fragment ตามทิศทาง/ลำดับ. อย่าใส่ cookie หรือ URL จากบทความลงระบบแข่งจริง.

หลักฐาน: frame range, stream id, transform และ output hash.
