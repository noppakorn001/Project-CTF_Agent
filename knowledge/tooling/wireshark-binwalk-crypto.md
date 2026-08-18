# Wireshark + binwalk + crypto: competition quick reference

เอกสารนี้เป็น operational checklist สำหรับ artifact ที่ได้รับอนุญาตเท่านั้น. ค่าเริ่มต้น
คือ offline/read-only; ห้ามใช้ `tshark -i` หรือทำ capture network ในโหมดนี้.

## 1. Preserve and inventory

```bash
sha256sum challenge.pcapng
file challenge.pcapng
stat --printf='size=%s mtime=%y\n' challenge.pcapng
```

สำหรับ APK/firmware ให้ hash ก่อนเช่นกัน. สร้าง derived workspace แยกและกำหนด cap:
input 256 MiB, output 64 MiB, nested depth 3, members/records 10,000 และ runtime 30 s
(ปรับลงตามโจทย์).

## 2. PCAP first pass

```bash
tshark -r challenge.pcapng -q -z io,phs
tshark -r challenge.pcapng -q -z conv,tcp
tshark -r challenge.pcapng -Y 'http || dns || tcp' \
  -T fields -e frame.number -e ip.src -e ip.dst -e tcp.stream -e _ws.col.Info
```

`-r` อ่านไฟล์ที่มีอยู่; `-Y` เป็น display filter. แยก capture filter (`-f`) ออกจาก display
filter และไม่ใช้ `-i` ใน challenge artifact workflow. สำหรับ stream ให้ export เฉพาะช่วง
ที่มีหลักฐาน:

```bash
tshark -r challenge.pcapng -Y 'tcp.stream == 2' -T fields \
  -e tcp.seq -e tcp.payload -E occurrence=a -E aggregator=,
```

For a bounded tabular first pass, use
[`tools/forensics/tshark_triage.py`](../../tools/forensics/tshark_triage.py). It
hashes the original, uses only `tshark -r`, caps the output, and rejects fields
that could be interpreted as command-line options. For example:

```bash
python3 tools/forensics/tshark_triage.py challenge.pcapng \
  --filter 'dns || http' --field frame.number --field dns.qry.name
```

The wrapper is an inventory aid, not a flag verifier: preserve the frame numbers,
filter, TShark version, and output hash before applying any decoder.

ต้องบันทึก frame/stream id, filter, tool version และ output hash. HTTP object ที่ export
แล้วเป็น derived evidence; ตรวจ signature/size ก่อน parse ต่อ.

## 3. Common crypto bridges

| Evidence | Bounded route | Verification |
| --- | --- | --- |
| zlib magic `78 01/5e/9c/da` ใน selected stream | try decompression at each offset with output cap | zlib checksum + source offset |
| DNS labels เป็น hex | exact suffix parser → order by frame → bytes | file magic + chunk count |
| handshake + encrypted callback | parse nonce/key map from supplied spec | decrypt/MAC/sequence replay |
| image channel code | extract declared channel/bit order | prefix/length + image hash |
| repeated RSA/ECC values | construct equations from source | raw encryption/signature replay |

## 4. Binwalk safe route

เริ่มด้วย identification-only; upstream อธิบายว่า binwalk ใช้ identify และ optionally
extract embedded files และ entropy ช่วยชี้ compression/encryption. ใน CTF-Agent ห้ามเริ่ม
ด้วย recursive `-e`:

```bash
binwalk --signature firmware.bin
file firmware.bin
```

ถ้าพบ signature ให้เลือก offset ที่สัมพันธ์กับ source แล้ว slice ด้วย byte cap, hash slice,
และตรวจด้วย `file`/central directory. Reject absolute/`..` paths, links, devices, duplicate
normalized names และ expansion ที่เกิน cap. ใช้ [binwalk_gate.py](../../tools/forensics/binwalk_gate.py)
เป็น wrapper ที่ไม่ extract.

## 5. Evidence and stop rules

ใช้รูปแบบ `artifact hash → frame/offset/member → transform → observed fact → inference`.
หยุดเมื่อ prerequisite ไม่ผ่านสองครั้ง, สาม action ไม่ได้ relation ใหม่, ถึง cap, หรือ parser
ให้ผลขัดกัน. Flag-shaped text ที่ไม่มี chain นี้เป็น `LEAD`, ไม่ใช่ `VERIFIED`.
