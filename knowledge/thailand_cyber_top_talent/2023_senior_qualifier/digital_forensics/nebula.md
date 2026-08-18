# Nebula — bounded media triage

**Status:** `RESEARCH_ONLY`  
**Input:** `Nebula.mp4` จากโจทย์จริงเท่านั้น (ต้องบันทึก SHA-256 ก่อนตรวจ)

## วิธีคิด

บทความรายงานว่าไฟล์วิดีโอมีข้อความต่อท้ายไฟล์ การตรวจที่เร็วและปลอดภัยคือ identify
ชนิด/ขนาด/EOF แล้วค้นข้อความ printable แบบมี cap ไม่ต้องเปิดวิดีโอหรือรัน codec แปลก ๆ

```bash
sha256sum Nebula.mp4
file Nebula.mp4
stat --printf='%s bytes\n' Nebula.mp4
strings -a -n 6 -t d Nebula.mp4 | tail -80
```

## หลักฐานที่ต้องเก็บ

บันทึก offset ของข้อความ, ขนาด original, hash ของไฟล์ และ flag format ที่ได้จาก source
เท่านั้น ถ้า string อยู่ใน metadata/ท้ายไฟล์ให้ยืนยันซ้ำด้วย `dd` แบบ bounded และ
เปรียบเทียบ bytes กับ original; ห้ามจัดว่า verified จาก `strings` เพียงอย่างเดียว

## Reusable lesson

`supported-playbook / forensics`: เมื่อ media container ถูกต้องแต่มี trailing bytes ให้
ตรวจ EOF และ printable run ก่อน stego brute force; stop เมื่อไม่มี relation กับ flag format
หรือพบข้อมูลเกิน cap.
