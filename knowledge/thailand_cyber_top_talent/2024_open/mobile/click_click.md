# Click Click — static XOR relation in APK

**Status:** `RESEARCH_ONLY`

ใช้ `jadx`/`apktool` ใน disposable workspace เมื่อได้รับอนุมัติ; ค้น function ที่รับ input
และเปรียบเทียบกับ constant/key. ถ้าเป็น XOR ต่อ character ให้ reconstruct relation แบบ
offline และ verify ด้วยการรันเฉพาะ test harness ที่ตัด UI/network ออก.

อย่าเก็บ credential หรือส่ง APK ไป model; บันทึก source path, constant hash และ candidate
verification output แทน.
