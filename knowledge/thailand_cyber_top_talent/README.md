# Thailand Cyber Top Talent research notes

สถานะของโฟลเดอร์นี้คือ `RESEARCH_ONLY` ไม่ใช่ผลการ submit และไม่มี flag ที่คัดลอก
จาก public write-up บันทึกไว้ เอกสารแต่ละใบสรุปเพียงสัญญาณ, ขั้นตอนตรวจสอบแบบ bounded,
หลักฐานที่ต้องเก็บ และจุดหยุดเมื่อข้อมูลไม่พอ เมื่อนำไปใช้กับโจทย์จริงต้องสร้าง workspace
ใหม่ เก็บ hash ของ artifact และทำ independent verification ตามนโยบายของ project

## แหล่งข้อมูล

- [CTF.in.th — write-up category](https://ctf.in.th/category/write-up/) — ผู้ใช้ระบุเป็นแหล่งหลัก; ดัชนีสาธารณะตอบกลับไม่ครบระหว่างการค้นคว้า จึงไม่ถือว่าเป็นหลักฐานของ flag
- [ShoIsMyName page 2](https://shoismyname.me/2/) และ [NCSA bootcamp notes](https://shoismyname.me/posts/2ncsabootcamp/) — ใช้สกัดวิธีคิดและประเภท artifact เท่านั้น
- [Thailand Cyber Top Talent 2023 qualifier write-up](https://blog.noonomyen.com/posts/ctf/thailand-cyber-top-talent-2023-senior-qualifier-writeup/)
- [Thailand Cyber Top Talent 2024 Open collection](https://www.safecloud.co.th/researches/blog/NCSA-2024-th)
- [Thailand Cyber Top Talent 2025 network write-up](https://blog.k1god.com/posts/thailand_cyber_top_talent_2025_online_senior_ctf_writeup/)
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Binwalk upstream](https://github.com/ReFirmLabs/binwalk)

## โครงสร้าง

- `2023_senior_qualifier/` — PCAP/HTTP export, DNS exfiltration, nested archive และ classical crypto
- `2024_open/` — chained encodings, emoji/binary, image LSB, encrypted C2 และ mobile/firmware triage
- `2025_online_senior/` — zlib stream และ custom UDP protocol reconstruction
- `../tooling/` — checklist และ command recipes ที่ยกไปใช้กับ artifact ใหม่ได้

## กติกาการใช้

1. ห้ามใช้ URL จาก write-up เป็น target; ใช้เฉพาะ instance ที่ operator allowlist ไว้
2. ห้ามรัน payload ที่ถูกฝังใน PCAP/APK/firmware บน host หลัก
3. แยก `lead` (ข้อความที่พบ) ออกจาก `verified` (replay จาก bytes ต้นฉบับ)
4. ห้ามใส่ flag จากบทความลงผลลัพธ์ของระบบโดยไม่มี artifact/transcript ของโจทย์นั้น
