# Hard — emoji bits and fixed offset

**Status:** `RESEARCH_ONLY`

นับ Unicode code point ต่อ token; ถ้ามี emoji สองค่าและ token ยาว 8 ให้ map เป็น bit แล้ว
จัดกลุ่มเป็น byte. จากนั้นตรวจ relation ระหว่าง decoded Unicode กับ flag prefix ที่โจทย์
กำหนด แทนการ guess offset จากภาพ.

ข้อควรระวัง: ใช้ `str`/code point ไม่ใช่ UTF-8 byte length, จำกัดจำนวน token และตรวจว่า
offset เดียวใช้ได้กับทุกตัวอักษร. บันทึก mapping และ output hash.
