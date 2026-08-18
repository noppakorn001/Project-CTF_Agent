# Encrypted C2 v2 — handshake-derived key material

**Status:** `RESEARCH_ONLY`

อย่าลอง decrypt ทุก cipher แบบ brute force. เริ่มจาก protocol hierarchy, isolate handshake
และ callback frames, parse length/nonce/key-map ตาม source/spec แล้ว replay decrypt offline.
ตรวจ padding/MAC/sequence ก่อนอ่านข้อความ.

หลักฐานคือ frame numbers, derived key hash (ไม่เก็บ secret ถ้าไม่จำเป็น), cipher parameters
และ plaintext hash. ถ้า handshake ไม่ครบ ให้ mark inconclusive.
