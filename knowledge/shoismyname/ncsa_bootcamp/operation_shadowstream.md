# Operation ShadowStream — decrypt with supplied private key

**Status:** `RESEARCH_ONLY`

ถ้ามี PCAP และ private key ที่โจทย์ให้ ให้ export terminal stream, แยก ciphertext blocks
ตาม protocol และ decrypt offline ด้วย algorithm/padding ที่ระบุ. ตรวจ key fingerprint และ
plaintext relation ก่อนบันทึกผล; ไม่ค้น/ใช้ key จากระบบอื่น.

เก็บ key hash/permissions อย่างระมัดระวังและลบ secret จาก audit log.
