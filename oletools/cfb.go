// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
)

// A reader for OLE2 compound files.
//
// A compound file is a FAT filesystem inside a file, designed in 1992 and still how
// Office stores legacy documents and how it stores the VBA project inside modern
// ones. Reading it is unavoidable: vbaProject.bin is a compound file even when the
// document around it is a zip.
//
// Written here rather than taken from a library to keep the core module's dependency
// list short — the whole format that matters is a header, two allocation tables and a
// directory, and the alternative is a dependency for four hundred lines.
//
// Every offset below is bounds-checked and every length is checked against what is
// actually present. The input is a document an attacker chose; a header field saying
// a stream is four gigabytes is a claim, not a fact.

const (
	cfbHeaderSize = 512
	dirEntrySize  = 128

	// Sector chain sentinels.
	sectEndOfChain = 0xFFFFFFFE
	sectFree       = 0xFFFFFFFF
	sectFAT        = 0xFFFFFFFD
	sectDIFAT      = 0xFFFFFFFC

	// Directory entry object types.
	objStream  = 2
	objRoot    = 5
	noStream   = 0xFFFFFFFF
	maxEntries = 1 << 16 // a document with 65k streams is not a document
)

var errNotCFB = errors.New("oletools: not a compound file")

type cfb struct {
	raw        []byte
	sectorSize int
	miniCutoff uint32
	fat        []uint32
	miniFAT    []uint32
	dir        []cfbEntry
	miniStream []byte
}

type cfbEntry struct {
	Name  string
	Type  byte
	Start uint32
	Size  uint64
}

func parseCFB(raw []byte) (*cfb, error) {
	if len(raw) < cfbHeaderSize || string(raw[:8]) != string(ole2Magic) {
		return nil, errNotCFB
	}

	sectorShift := binary.LittleEndian.Uint16(raw[30:32])
	// Only the two shifts the format defines. Anything else is a malformed header
	// and 1<<shift on an arbitrary value is how you allocate a petabyte.
	if sectorShift != 9 && sectorShift != 12 {
		return nil, errNotCFB
	}
	c := &cfb{
		raw:        raw,
		sectorSize: 1 << sectorShift,
		miniCutoff: binary.LittleEndian.Uint32(raw[56:60]),
	}
	if c.miniCutoff == 0 || c.miniCutoff > 1<<20 {
		c.miniCutoff = 4096
	}

	if err := c.readFAT(); err != nil {
		return nil, err
	}
	if err := c.readDirectory(); err != nil {
		return nil, err
	}
	c.readMiniFAT()
	return c, nil
}

// sector returns one sector's bytes, or nil if it is not there. Sector n begins at
// (n+1) * sectorSize, because sector -1 is the header.
func (c *cfb) sector(n uint32) []byte {
	if n >= sectFAT {
		return nil
	}
	off := (int64(n) + 1) * int64(c.sectorSize)
	end := off + int64(c.sectorSize)
	if off < 0 || end > int64(len(c.raw)) {
		return nil
	}
	return c.raw[off:end]
}

// readFAT assembles the allocation table from the DIFAT.
func (c *cfb) readFAT() error {
	raw := c.raw
	numFAT := binary.LittleEndian.Uint32(raw[44:48])
	if numFAT > uint32(len(raw)/c.sectorSize)+1 {
		return errNotCFB
	}

	// The first 109 FAT sector numbers live in the header; the rest are chained
	// through DIFAT sectors.
	var fatSectors []uint32
	for i := 0; i < 109 && uint32(i) < numFAT; i++ {
		fatSectors = append(fatSectors, binary.LittleEndian.Uint32(raw[76+i*4:80+i*4]))
	}

	next := binary.LittleEndian.Uint32(raw[68:72])
	for guard := 0; next < sectFAT && guard < 1<<16 && uint32(len(fatSectors)) < numFAT; guard++ {
		s := c.sector(next)
		if s == nil {
			break
		}
		perSector := c.sectorSize/4 - 1
		for i := 0; i < perSector && uint32(len(fatSectors)) < numFAT; i++ {
			fatSectors = append(fatSectors, binary.LittleEndian.Uint32(s[i*4:i*4+4]))
		}
		next = binary.LittleEndian.Uint32(s[len(s)-4:])
	}

	for _, fs := range fatSectors {
		s := c.sector(fs)
		if s == nil {
			continue
		}
		for i := 0; i+4 <= len(s); i += 4 {
			c.fat = append(c.fat, binary.LittleEndian.Uint32(s[i:i+4]))
		}
	}
	if len(c.fat) == 0 {
		return errNotCFB
	}
	return nil
}

// chain walks a sector chain and returns the concatenated bytes, bounded by size.
//
// The guard is not optional: a malformed or malicious FAT can contain a cycle, and
// following one is an infinite loop in a service that parses attacker-supplied files.
func (c *cfb) chain(start uint32, size uint64, mini bool) []byte {
	if size == 0 {
		return nil
	}
	unit := c.sectorSize
	if mini {
		unit = 64
	}
	if size > uint64(len(c.raw))*8 {
		// A claimed size far larger than the file itself. Trust the file.
		size = uint64(len(c.raw))
	}

	out := make([]byte, 0, size)
	seen := make(map[uint32]bool)
	table := c.fat
	if mini {
		table = c.miniFAT
	}

	for s := start; s < sectFAT && uint64(len(out)) < size; {
		if seen[s] {
			break // a cycle
		}
		seen[s] = true

		var data []byte
		if mini {
			off := int(s) * unit
			if off < 0 || off+unit > len(c.miniStream) {
				break
			}
			data = c.miniStream[off : off+unit]
		} else {
			data = c.sector(s)
		}
		if data == nil {
			break
		}
		need := size - uint64(len(out))
		if uint64(len(data)) > need {
			data = data[:need]
		}
		out = append(out, data...)

		if int(s) >= len(table) {
			break
		}
		s = table[s]
	}
	return out
}

func (c *cfb) readDirectory() error {
	first := binary.LittleEndian.Uint32(c.raw[48:52])

	var raw []byte
	seen := make(map[uint32]bool)
	for s := first; s < sectFAT; {
		if seen[s] || len(raw) > maxEntries*dirEntrySize {
			break
		}
		seen[s] = true
		data := c.sector(s)
		if data == nil {
			break
		}
		raw = append(raw, data...)
		if int(s) >= len(c.fat) {
			break
		}
		s = c.fat[s]
	}
	if len(raw) < dirEntrySize {
		return errNotCFB
	}

	for off := 0; off+dirEntrySize <= len(raw); off += dirEntrySize {
		e := raw[off : off+dirEntrySize]
		typ := e[66]
		if typ != objStream && typ != objRoot && typ != 1 {
			continue
		}
		nameLen := int(binary.LittleEndian.Uint16(e[64:66]))
		if nameLen < 2 || nameLen > 64 {
			nameLen = 0
		}
		c.dir = append(c.dir, cfbEntry{
			Name:  decodeUTF16(e[:nameLen]),
			Type:  typ,
			Start: binary.LittleEndian.Uint32(e[116:120]),
			Size:  binary.LittleEndian.Uint64(e[120:128]),
		})
	}
	return nil
}

// readMiniFAT loads the table and the backing stream for small streams. Streams
// below the cutoff are packed into the root entry's stream rather than given whole
// sectors, which is why a VBA module of a few hundred bytes is not where a naive
// reader looks for it.
func (c *cfb) readMiniFAT() {
	numMini := binary.LittleEndian.Uint32(c.raw[64:68])
	first := binary.LittleEndian.Uint32(c.raw[60:64])
	if numMini == 0 || first >= sectFAT {
		return
	}

	seen := make(map[uint32]bool)
	for s := first; s < sectFAT && uint32(len(seen)) < numMini+1; {
		if seen[s] {
			break
		}
		seen[s] = true
		data := c.sector(s)
		if data == nil {
			break
		}
		for i := 0; i+4 <= len(data); i += 4 {
			c.miniFAT = append(c.miniFAT, binary.LittleEndian.Uint32(data[i:i+4]))
		}
		if int(s) >= len(c.fat) {
			break
		}
		s = c.fat[s]
	}

	for _, e := range c.dir {
		if e.Type == objRoot {
			c.miniStream = c.chain(e.Start, e.Size, false)
			break
		}
	}
}

// Open returns a stream's bytes by directory entry.
func (c *cfb) Open(e cfbEntry) []byte {
	if e.Type != objStream {
		return nil
	}
	return c.chain(e.Start, e.Size, uint64(e.Size) < uint64(c.miniCutoff))
}

// Find returns the first stream whose name matches, case-insensitively.
func (c *cfb) Find(name string) (cfbEntry, bool) {
	for _, e := range c.dir {
		if e.Type == objStream && strings.EqualFold(e.Name, name) {
			return e, true
		}
	}
	return cfbEntry{}, false
}

// decodeUTF16 reads a directory entry name, which is UTF-16LE with a trailing NUL
// counted in its length.
func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i : i+2])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}
