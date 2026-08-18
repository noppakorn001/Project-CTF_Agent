# Decrypt message — key-list validation

**Status:** `RESEARCH_ONLY`

เมื่อมี `encrypt.py`, `secret.txt` และ `key.txt` ให้ตรวจ algorithm และ encoding ก่อน
ลอง key แต่ละบรรทัดแบบ bounded. สำหรับ Fernet ให้ใช้ library ที่โจทย์ระบุและยอมรับเฉพาะ
plaintext ที่ผ่าน expected prefix/format; อย่าเขียน decrypted output ลง path เดิม

```python
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

secret = Path("secret.txt").read_bytes()
for raw in Path("key.txt").read_text().splitlines()[:10000]:
    try:
        plain = Fernet(raw.encode("ascii")).decrypt(secret)
    except (InvalidToken, ValueError, UnicodeError):
        continue
    print(plain[:256])
    break
```

บันทึก hash ของ input, key line number และ plaintext hash; verifier ต้อง replay จาก clean
copy และไม่เก็บ key ที่ไม่เกี่ยวข้องใน audit.
