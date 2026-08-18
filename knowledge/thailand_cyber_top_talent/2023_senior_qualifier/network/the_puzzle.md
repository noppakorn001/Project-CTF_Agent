# The puzzle — HTTP object to damaged QR

**Status:** `RESEARCH_ONLY`

1. อ่าน PCAP แบบ offline และสรุป protocol/endpoint ก่อน
2. ใช้ Wireshark `File → Export Objects → HTTP` หรือ TShark เพื่อเลือก object ที่ frame อ้างถึง
3. ตรวจ magic, dimensions และ hash ของภาพที่ export แล้วจึงซ่อมเฉพาะส่วนที่ขาดตาม evidence
4. decode QR ในเครื่อง; ไม่ follow URL ที่ QR ชี้โดยอัตโนมัติ

ตัวอย่าง triage:

```bash
tshark -r challenge.pcapng -q -z io,phs
tshark -r challenge.pcapng -Y 'http' -T fields \
  -e frame.number -e ip.src -e ip.dst -e http.request.uri
```

ถ้า QR ขาด finder/position marker ให้บันทึก pixel coordinates และ hash ของภาพที่แก้ไข
เป็น derived evidence แยกจาก original. Candidate จาก URL เป็นเพียง lead จนกว่าจะมี
artifact-local verifier.
