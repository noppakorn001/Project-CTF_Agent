# The Face THCTT24 — identification-only embedded-file search

**Status:** `RESEARCH_ONLY`

APK เป็น ZIP container ที่อาจมี asset ซ้อนอยู่ ให้ทำ central-directory listing และ
`binwalk` identification-only ก่อน. เลือก member/offset ที่เกี่ยวข้องตามชื่อ/size แล้ว
extract ด้วย cap; ห้าม recursive extraction หรือรัน DEX/native code บน host.

```bash
binwalk --signature TheFaceTHCTT24.apk
```

บันทึก APK hash, member path/offset และ hash ของ derived asset.
