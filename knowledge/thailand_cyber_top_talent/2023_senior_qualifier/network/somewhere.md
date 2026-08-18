# SOMEWHERE — mixed traffic, HTTP-first triage

**Status:** `RESEARCH_ONLY`

เมื่อ PCAP มีหลาย protocol ให้เริ่มด้วย protocol hierarchy และ conversation counts ไม่ใช่
ค้น flag ทั้งไฟล์. ถ้า HTTP มี object ที่เกี่ยวข้อง ให้ export object แล้วตรวจ metadata,
signature และ trailing bytes. อ้าง frame range และ object hash ใน evidence timeline.

Stop condition: ถ้า object ไม่สัมพันธ์กับ challenge statement หลังสาม bounded checks ให้
หยุด route และส่งต่อไปหมวดที่เหมาะสม แทนการเปิด payload ทั้งหมดเข้าโมเดล.
