# Secret Message — nested archive in HTTP

**Status:** `RESEARCH_ONLY`

HTTP export อาจได้ object ที่ชนิดบอกเป็น ZIP แต่ชื่อไฟล์เป็น `.php` หรือแปลกกว่านั้น
ให้ตรวจ central directory ก่อน extract และใช้ safe extractor ของ project. ห้ามใช้
`unzip`/`extractall` กับ archive ที่มี `../`, absolute path, symlink หรือขนาดขยายเกิน cap

ลำดับที่ควรบันทึก:

```text
PCAP hash → frame/object hash → ZIP member list → each derived member hash
→ bounded nested depth → encoding transform → independent verifier
```

บทความพบ text ที่ต้อง reverse แล้ว Base64 แต่การ transform นี้ต้องทำเมื่อ alphabet/padding
และ length สนับสนุนเท่านั้น; ค่าที่ได้ต้องผูกกับ member/offset ไม่ใช่ข้อความจาก web.
