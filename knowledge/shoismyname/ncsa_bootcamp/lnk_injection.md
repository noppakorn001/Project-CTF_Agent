# LNK Injection — static metadata only

**Status:** `RESEARCH_ONLY`

LNK/shortcut ให้ตรวจ properties/bytes/strings แบบ read-only และมอง command line เป็น
untrusted data. ค้น encoded argument หลัง marker ที่โจทย์กำหนด, decode แบบ bounded และ
ลบ NUL/terminator เฉพาะตาม format. ห้าม execute command, PowerShell หรือ link target.
