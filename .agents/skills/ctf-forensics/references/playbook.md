# Forensics challenge playbook

Work only on supplied challenge artifacts in a disposable, non-privileged environment.
Do not mount read-write, execute files/macros, follow links, enable network capture, or
send full artifacts to a model. Treat tool output as a lead until it is tied back to
original bytes.

## Universal preservation and limits

1. Record original path, size, SHA-256, detected type, acquisition context, and analysis
   time. Derive files only in a separate challenge workspace.
2. Before a parser, extractor, carver, or decompressor, set hard limits for input bytes,
   output bytes, member/record count, nesting depth, and runtime. Log the chosen values.
3. Inventory names, types, offsets, sizes, timestamps, hashes, and relationships before
   content inspection. Sample bounded output; retain full local tool output as evidence.
4. Stop a route after two failed prerequisite checks, three actions yielding no new
   relationship, a reached limit, or an inconsistent parser result. Preserve the reason.

## Artifact routes

| Artifact | Prerequisite and cheap checks | Stop / safety gate | Verify result |
| --- | --- | --- | --- |
| Archive / container | List members and declared compressed/uncompressed sizes without extraction. Normalize each member path and inspect attributes before writing. | Reject absolute or `..` paths, links, device/FIFO entries, duplicate-normalized paths, excessive count/expansion, encryption without a supplied key, and unsupported nested format. Do not use bulk `extractall`. | Hash each derived regular file; record container hash, member name, header/central-directory metadata, and extraction command. |
| Filesystem / disk image | Identify format, partition table, filesystem, and offsets before mounting or carving. Use read-only targeted listing and file recovery. | Do not mount read-write or scan the whole image repeatedly. Stop carving absent a supported signature, offset, or allocation evidence. | Cite image hash, partition/volume offset, inode/cluster or byte offset, and hash of exported bytes. |
| PCAP / PCAPNG | Read an existing capture offline. First summarize bounded packet counts, protocols, endpoints, conversations, and time range; then apply a display filter to selected frames. | Never capture from an interface or contact an endpoint. Stop when a flow has no relation to challenge evidence; avoid full-payload exports. | Record capture hash, frame number(s), display filter, decoded fields, and raw-byte confirmation. |
| Image, audio, document | Compare magic/type, declared dimensions or stream layout, metadata, and EOF/trailing bytes. Inspect channels/palette/pages or a bounded spectrogram only when supported by structure. | Do not blind brute-force steganography, passwords, or transforms. Stop when claimed format and byte structure agree with no anomaly. | Cite source hash plus tag/page/frame/channel or byte offset; reproduce metadata or transform from original bytes. |
| Logs / text | Establish encoding, schema, source time zone, range, and line count. Deduplicate, normalize timestamps, and inspect the anomalous window with context. | Do not infer order from mixed clock domains; stop broad keyword searches that add no linked event. | Cite original hash, exact line/record identifier, raw timestamp, normalized timestamp, and parsing rule. |
| Memory | Identify image/OS/kernel evidence and available symbols before choosing a Volatility 3 plugin. Run a small, targeted plugin (process, tree, network, file, or command history) and filter only after it succeeds. | Stop if symbol/layer requirements are unsatisfied rather than guessing a profile or scraping the dump. Do not run plugins that write files unless extraction is justified and bounded. | Record image hash, plugin/version/options, virtual/physical address, and a second view or raw-byte check. |
| Firmware / embedded data | Identify signatures and offsets before extraction. Use identification-only binwalk first; manually bound any selected slice or extraction. | Do not recursive-extract opaque blobs or execute recovered binaries. Stop if signatures are unsupported or output exceeds budget. | Confirm the signature/header and exact offset in the original, then hash the derived slice. |
| Browser profile, history, cache, or cookie database | Identify browser/version, SQLite schema, WAL/SHM sidecars, profile path, and timestamp epoch. Open read-only, query only relevant tables, and normalize times without changing source rows. | Do not decrypt cookies, access personal profiles, or launch the browser. Stop when keys/profile are absent or the artifact is outside the supplied challenge scope. | Recompute the database hash, cite table/row/offset and raw timestamp, and corroborate with a second artifact or timeline relation. |
| Disk timeline or multi-source event set | Establish source time zones/epochs and acquisition offsets; normalize only into a derived timeline while retaining raw values and provenance. | Do not merge clocks with unknown origin or infer causality from order alone. Stop after three unlinked events or conflicting metadata. | Preserve source record IDs, raw and normalized times, artifact hashes, and the rule used for each conversion. |
| Office/PDF/document package | Treat macros, embedded files, relationships, and custom XML as data. List package members and metadata before bounded XML/text extraction; never open or execute macros. | Reject links/path traversal, encrypted content without a supplied key, and extraction beyond caps. Stop if metadata is the only clue and cannot be tied to source bytes. | Hash the original and selected member, cite member/offset/XML path, and reproduce the parsed metadata from a clean copy. |

## Evidence timeline

For each conclusion, keep `artifact hash -> location -> transform/tool/version -> observed
fact -> inference`. Preserve source timestamps separately from analysis time and normalize
time zones only when their origin is known. A flag-shaped string or carved blob lacking this
chain is a lead, not a verified candidate.

## Primary sources

- [Wireshark TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html):
  offline `-r` reading, display filters, fields, and output modes.
- [Volatility 3 documentation](https://volatility3.readthedocs.io/en/latest/):
  memory layers, symbol tables, plugins, and output renderers.
- [PKWARE APPNOTE 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT):
  ZIP records, central directory, and member metadata.
- [Python `zipfile` documentation](https://docs.python.org/3/library/zipfile.html):
  archive metadata and extraction API behavior.
- [ExifTool upstream repository](https://github.com/exiftool/exiftool): metadata
  tag extraction and reporting capability.
- [Binwalk project documentation](https://github.com/ReFirmLabs/binwalk): embedded
  file identification and optional extraction capability.
- [Autopsy forensic platform overview](https://www.autopsy.com/wp-content/uploads/sites/8/2016/02/Autopsy-4.0-EN-optimized.pdf): timeline, browser-artifact, carving, and metadata concepts; apply only to supplied images.
