# Lineman — visual classical-cipher triage

**Status:** `RESEARCH_ONLY`

เมื่อรูปมี glyph ซ้ำเป็นชุด ให้ตรวจรูปทรง/จำนวนช่องและเปรียบเทียบกับ classical cipher
catalog แบบ bounded. ถ้ารูปทรงตรงกับ Pigpen ให้บันทึก mapping table ที่ใช้และถอดเฉพาะ
สัญลักษณ์ที่เห็น; อย่าส่งภาพทั้งภาพไป external decoder และอย่าเดา flag จากภาพ preview.

หลักฐานที่ต้องเก็บคือ original image hash, crop coordinates, mapping version และ decoded
text hash. ถ้าไม่พบ mapping ที่สอดคล้องกันหลังสอง hypothesis ให้หยุด.
