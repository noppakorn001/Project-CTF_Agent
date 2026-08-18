# Research log: CTT write-up study

วันที่ค้นคว้า: 2026-08-14 (เวลาไทย)  
ขอบเขต: เทคนิคสำหรับ CTF ที่ผู้ใช้ระบุ ไม่ติดต่อ challenge instance และไม่บันทึก flag

## สิ่งที่สกัดได้

| สัญญาณ | cheap check | route ที่ควรเลือก | หลักฐานยืนยัน |
| --- | --- | --- | --- |
| PCAP มี HTTP object | protocol hierarchy แล้วดู `http`/`tcp.stream` | export object แบบอ่านอย่างเดียว | hash ของ object + frame range |
| DNS query ยาวเท่ากันและเป็น hex | `tshark -T fields -e dns.qry.name` | ลบ suffix, validate hex, ต่อ chunk ตามลำดับ | magic/header ของไฟล์และ hash |
| TCP stream มี base64/zlib | inspect bounded stream ไม่ค้นทั้งไฟล์แบบไม่จำกัด | decode candidate ที่มี header/CRC ตรง | decoded bytes + source frame |
| ภาพมี code ใน channel ต่ำสุด | เปรียบเทียบ dimensions/type/EOF ก่อน | extract channel เดียวตาม source evidence | printable prefix + image hash |
| firmware/APK มี embedded archive | `binwalk` identification-only และ `file` | เลือก offset ที่มี signature แล้ว slice แบบ bounded | offset + hash ของ slice |
| emoji หรือ glyph มีจำนวนคงที่ | นับ code point ต่อ token ไม่ใช่ byte | map bit/byte แล้วทดสอบ relation ที่สังเกตได้ | offset/token count + transform |
| custom protocol มี magic/version | parse header/length/sequence จาก spec | reassemble เฉพาะ frames ที่ตรง predicate | record count + checksum/length |

## Negative lessons

- `strings` ที่พบ flag-shaped text เป็นเพียง lead; ต้องอ้าง offset และตรวจจาก original bytes
- อย่า `extractall` ZIP/APK หรือใช้ recursive binwalk โดยไม่มี member/size/depth cap
- อย่า follow redirect จาก QR/HTTP object ระหว่าง triage เพราะไม่ใช่หลักฐานของโจทย์
- อย่าใช้ “Magic”/brute-force เป็น first action เมื่อมี file signature, protocol spec หรือ key material ให้ตรวจได้

## 2026 source review (no challenge solve claimed)

The requested [CTF.in.th write-up index](https://ctf.in.th/category/write-up/)
returned HTTP 403 to the research fetcher, so it was not treated as evidence or
copied into a result. [ShoIsMyName's CTF archive](https://shoismyname.me/archive/?category=CTF-Writeup)
was readable; its posts were used only to confirm portable signals such as IDOR
parameter review, bounded `strings`/XOR checks, chained Caesar/Vigenere/XOR, and
PCAP stream triage. URLs, cookies, proof codes, and flags shown in those posts
remain excluded from the project.

The primary tool references reviewed were the [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html),
the [Wireshark display-filter reference](https://www.wireshark.org/docs/man-pages/wireshark-filter.html),
and the [Binwalk project documentation](https://github.com/ReFirmLabs/binwalk).
The local implementation keeps these routes offline/read-only: TShark uses
`-r` field exports only, while Binwalk is identification-only and has a byte/time
cap. Recursive extraction, live capture, and target contact remain operator-gated.
