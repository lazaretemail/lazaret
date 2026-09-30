// SPDX-License-Identifier: AGPL-3.0-only

package eml

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/emersion/go-message"

	"github.com/lazaretemail/lazaret/mdm"
)

// addAttachment records one file carried by the message.
//
// Three different answers to "what kind of file is this?" are kept, because attackers make
// them disagree on purpose: the declared Content-Type, the extension on the filename, and
// the type implied by the leading bytes. A .pdf that is really a zip, or a Content-Type of
// text/plain on an executable, is exactly the sort of thing rules look for.
func (p *parser) addAttachment(m *mdm.MessageDataModel, e *message.Entity, mediaType string, params map[string]string, body []byte) {
	a := &mdm.Attachment{Raw: body, Size: mdm.Ptr(int64(len(body)))}

	if mediaType != "" {
		a.ContentType = mdm.Ptr(mediaType)
	}
	if cte := e.Header.Get("Content-Transfer-Encoding"); cte != "" {
		a.ContentTransferEncoding = mdm.Ptr(strings.ToLower(cte))
	}
	if cid := e.Header.Get("Content-Id"); cid != "" {
		a.ContentID = mdm.Ptr(strings.Trim(strings.TrimSpace(cid), "<>"))
	}

	disp, dispParams, err := e.Header.ContentDisposition()
	if err == nil && disp != "" {
		a.ContentDisposition = mdm.Ptr(strings.ToLower(disp))
	}

	name := firstNonEmpty(dispParams["filename"], params["name"])
	if name != "" {
		if decoded, err := new(mime.WordDecoder).DecodeHeader(name); err == nil && decoded != "" {
			name = decoded
		}
		// A filename is attacker-controlled text that ends up in logs and UIs. Strip the
		// path separators and control characters that make it dangerous, but keep
		// everything else: rules match on the name exactly as sent, including the
		// right-to-left overrides used to disguise an extension.
		name = sanitiseFilename(name)
		a.FileName = mdm.Ptr(name)

		if ext := strings.TrimPrefix(strings.ToLower(path.Ext(name)), "."); ext != "" {
			a.FileExtension = mdm.Ptr(ext)
		}
	}

	if len(body) > 0 {
		md5sum := md5.Sum(body)
		sha1sum := sha1.Sum(body)
		sha256sum := sha256.Sum256(body)
		a.MD5 = mdm.Ptr(hex.EncodeToString(md5sum[:]))
		a.SHA1 = mdm.Ptr(hex.EncodeToString(sha1sum[:]))
		a.SHA256 = mdm.Ptr(hex.EncodeToString(sha256sum[:]))

		if ft := detectFileType(body, a.FileExtension); ft != "" {
			a.FileType = mdm.Ptr(ft)
		}
	}

	m.Attachments = append(m.Attachments, a)
}

// sanitiseFilename removes path traversal and control characters without otherwise
// altering the name.
func sanitiseFilename(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	// Take the last path element under either separator; attackers use both.
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	return strings.TrimSpace(name)
}

// magic maps leading bytes to the file_type values the schema enumerates.
//
// Content sniffing rather than trusting the declared type is the point of this table: the
// declared type is whatever the sender chose.
var magic = []struct {
	prefix []byte
	typ    mdm.AttachmentFileType
}{
	{[]byte("%PDF"), mdm.AttachmentFileTypePdf},
	{[]byte{0x50, 0x4b, 0x03, 0x04}, mdm.AttachmentFileTypeZip}, // also docx/xlsx/pptx; refined below
	{[]byte{0x50, 0x4b, 0x05, 0x06}, mdm.AttachmentFileTypeZip},
	{[]byte{0x50, 0x4b, 0x07, 0x08}, mdm.AttachmentFileTypeZip},
	{[]byte{0xd0, 0xcf, 0x11, 0xe0}, mdm.AttachmentFileTypeDoc}, // OLE2 compound file
	{[]byte{0x52, 0x61, 0x72, 0x21}, mdm.AttachmentFileTypeRar},
	{[]byte{0x37, 0x7a, 0xbc, 0xaf}, mdm.AttachmentFileTypeN7z},
	{[]byte{0x1f, 0x8b}, mdm.AttachmentFileTypeGz},
	{[]byte{0x42, 0x5a, 0x68}, mdm.AttachmentFileTypeBz2},
	{[]byte{0xfd, 0x37, 0x7a, 0x58, 0x5a}, mdm.AttachmentFileTypeXz},
	{[]byte{0x7f, 0x45, 0x4c, 0x46}, mdm.AttachmentFileTypeElf},
	{[]byte{0x4d, 0x5a}, mdm.AttachmentFileTypeExe},
	{[]byte{0x89, 0x50, 0x4e, 0x47}, mdm.AttachmentFileTypePng},
	{[]byte{0xff, 0xd8, 0xff}, mdm.AttachmentFileTypeJpg},
	{[]byte("GIF8"), mdm.AttachmentFileTypeGif},
	{[]byte("BM"), mdm.AttachmentFileTypeBmp},
	{[]byte("RIFF"), mdm.AttachmentFileTypeWebp}, // refined below
	{[]byte("{\\rtf"), mdm.AttachmentFileTypeRtf},
	{[]byte("ID3"), mdm.AttachmentFileTypeMp3},
	{[]byte("OggS"), mdm.AttachmentFileTypeOgg},
	{[]byte("wOFF"), mdm.AttachmentFileTypeWoff},
	{[]byte("wOF2"), mdm.AttachmentFileTypeWoff2},
	{[]byte("BEGIN:VCALENDAR"), mdm.AttachmentFileTypeIcs},
	{[]byte("SQLite format 3"), mdm.AttachmentFileTypeSqlite},
	{[]byte{0x4c, 0x00, 0x00, 0x00}, mdm.AttachmentFileTypeUnknown}, // .lnk; no schema value
}

func detectFileType(body []byte, ext *string) mdm.AttachmentFileType {
	for _, m := range magic {
		if len(body) < len(m.prefix) || !hasPrefix(body, m.prefix) {
			continue
		}
		typ := m.typ

		// OOXML documents are zip containers. The extension is the only cheap way to tell
		// them apart without reading the central directory, so it refines the answer here
		// rather than overriding it.
		if typ == mdm.AttachmentFileTypeZip && ext != nil {
			switch *ext {
			case "docx":
				return mdm.AttachmentFileTypeDocx
			case "xlsx":
				return mdm.AttachmentFileTypeXlsx
			case "pptx":
				return mdm.AttachmentFileTypePptx
			case "epub":
				return mdm.AttachmentFileTypeEpub
			}
		}
		if typ == mdm.AttachmentFileTypeDoc && ext != nil {
			switch *ext {
			case "xls":
				return mdm.AttachmentFileTypeXls
			case "ppt":
				return mdm.AttachmentFileTypePpt
			}
		}
		if typ == mdm.AttachmentFileTypeWebp && len(body) >= 12 {
			switch string(body[8:12]) {
			case "WEBP":
				return mdm.AttachmentFileTypeWebp
			case "WAVE":
				return mdm.AttachmentFileTypeWav
			case "AVI ":
				return mdm.AttachmentFileTypeAvi
			}
			return mdm.AttachmentFileTypeUnknown
		}
		return typ
	}

	// Nothing recognised. Fall back to the standard library's sniffer for the text and
	// image types it knows, then give up honestly rather than trusting the declared type.
	switch ct := http.DetectContentType(body); {
	case strings.HasPrefix(ct, "text/html"):
		return mdm.AttachmentFileTypeHTML
	case strings.HasPrefix(ct, "image/svg"):
		return mdm.AttachmentFileTypeSvg
	}
	return mdm.AttachmentFileTypeUnknown
}

func hasPrefix(b, prefix []byte) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == string(prefix)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
