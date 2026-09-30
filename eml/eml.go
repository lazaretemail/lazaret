// SPDX-License-Identifier: AGPL-3.0-only

// Package eml turns raw RFC 822 messages into the Message Data Model.
//
// This is the most attacker-exposed code in the platform. Every byte it reads was chosen by
// someone who would rather the message were not analysed, and malformed MIME is a
// deliberate evasion technique rather than an accident. The parser is therefore relentlessly
// tolerant: it records what it could not understand in the model's _errors field and
// carries on, because a message that fails to parse is a message no rule gets to inspect.
package eml

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // registers the common non-UTF-8 charsets

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/orgconfig"
)

// maxParts bounds the MIME tree. A message nesting thousands of empty parts is not a
// message, it is a resource-exhaustion attempt.
const maxParts = 5000

// maxPartBytes bounds how much of any single part is retained.
const maxPartBytes = 64 << 20

// Options control parsing.
type Options struct {
	// Org identifies the receiving organisation, which is what makes the message's
	// direction knowable. With no org configured, type.inbound and friends are left null
	// rather than guessed, and rules that depend on them evaluate as indeterminate.
	Org *orgconfig.Config

	// Now fixes the clock, for deterministic tests.
	Now func() time.Time
}

func (o *Options) now() time.Time {
	if o != nil && o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}

// Parse reads a raw message into the Message Data Model.
//
// It returns a model even when parts of the message are broken; a non-nil error means
// nothing at all could be read. Recoverable problems are recorded in the model's _errors.
func Parse(raw []byte, opts *Options) (*mdm.MessageDataModel, error) {
	if len(raw) == 0 {
		return nil, errors.New("eml: empty message")
	}

	p := &parser{opts: opts, raw: raw}

	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil {
		// go-message reports an unknown charset or transfer encoding by returning both an
		// error and a usable entity: the headers parsed, only the body decoding is
		// uncertain. That is worth recording but never worth discarding the message for.
		if entity == nil {
			// The header block itself is unreadable. Rather than give up — a message we
			// refuse to parse is a message no rule gets to inspect — treat the whole input
			// as a bare body. Truncated spool files and pasted message fragments both
			// arrive looking like this, and their content is still worth matching on.
			p.recordf("header", "unreadable header block, treating the input as a bare body: %v", err)
			entity, err = message.New(message.Header{}, bytes.NewReader(raw))
			if err != nil || entity == nil {
				return nil, fmt.Errorf("eml: %w", err)
			}
		} else {
			p.recordf("header", "%v", err)
		}
	}

	m := &mdm.MessageDataModel{
		Meta: &mdm.Metadata{
			CanonicalID: canonicalID(raw),
			CreatedAt:   opts.now(),
		},
	}

	p.parseHeaders(m, entity.Header)
	p.walkBody(m, entity)
	p.buildBody(m)
	p.classify(m)

	m.Errors = p.errs
	return m, nil
}

// ParseString is Parse for a message already in memory as a string.
func ParseString(raw string, opts *Options) (*mdm.MessageDataModel, error) {
	return Parse([]byte(raw), opts)
}

// parser carries state across the passes that build one model.
type parser struct {
	opts *Options
	raw  []byte

	errs []map[string]string

	// collected during the MIME walk
	plain []textPart
	html  []textPart
	parts int
}

// textPart is one decoded text/* body part, kept with the metadata rules can see.
type textPart struct {
	text     string
	charset  string
	encoding string
}

// recordf notes a non-fatal problem. These surface in the model's _errors field, which is
// the only honest way to say "this message was strange" without dropping it.
func (p *parser) recordf(where, format string, args ...any) {
	if len(p.errs) >= 64 {
		return // a pathological message should not produce an unbounded error list
	}
	p.errs = append(p.errs, map[string]string{
		"where": where,
		"error": fmt.Sprintf(format, args...),
	})
}

// walkBody traverses the MIME tree, collecting text parts and attachments.
//
// The classification question at each leaf is "is this content to read, or a file that came
// along with it?" — and attackers exploit every ambiguity in that question, so the rules for
// deciding are spelled out in isAttachment rather than left implicit.
func (p *parser) walkBody(m *mdm.MessageDataModel, root *message.Entity) {
	err := root.Walk(func(path []int, e *message.Entity, err error) error {
		if err != nil {
			p.recordf(partPath(path), "%v", err)
			return nil // keep walking: one broken part must not hide the rest
		}
		if p.parts++; p.parts > maxParts {
			p.recordf("body", "stopped after %d parts", maxParts)
			return errStopWalk
		}

		mediaType, params, ctErr := e.Header.ContentType()
		if ctErr != nil {
			p.recordf(partPath(path), "content-type: %v", ctErr)
		}
		mediaType = strings.ToLower(mediaType)

		// Multipart containers hold no content of their own; Walk descends into them.
		if strings.HasPrefix(mediaType, "multipart/") {
			return nil
		}

		body, readErr := readLimited(e.Body, maxPartBytes)
		if readErr != nil {
			p.recordf(partPath(path), "reading body: %v", readErr)
		}

		if p.isAttachment(e, mediaType) {
			p.addAttachment(m, e, mediaType, params, body)
			return nil
		}

		part := textPart{
			text:     string(body),
			charset:  params["charset"],
			encoding: e.Header.Get("Content-Transfer-Encoding"),
		}
		switch mediaType {
		case "text/html":
			p.html = append(p.html, part)
		case "text/plain", "":
			p.plain = append(p.plain, part)
		default:
			// Some other text/* subtype presented inline. Treat it as plain text: rules
			// searching the body should still see it.
			if strings.HasPrefix(mediaType, "text/") {
				p.plain = append(p.plain, part)
			} else {
				p.addAttachment(m, e, mediaType, params, body)
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		p.recordf("body", "%v", err)
	}
}

var errStopWalk = errors.New("stop walk")

// isAttachment decides whether a leaf part is a file rather than message content.
//
// Content-Disposition is the intended signal but is frequently absent or wrong, so a
// filename anywhere in the part's headers is treated as decisive. An inline image with a
// Content-ID is content by reference rather than an attachment to scan, but it is still
// reported as one: rules inspect inline images for QR codes and logos.
func (p *parser) isAttachment(e *message.Entity, mediaType string) bool {
	disp, params, err := e.Header.ContentDisposition()
	if err == nil {
		switch strings.ToLower(disp) {
		case "attachment":
			return true
		case "inline":
			// Inline text is content; anything else inline is a file that happens to be
			// displayed in place.
			if strings.HasPrefix(mediaType, "text/") && params["filename"] == "" {
				return false
			}
			return true
		}
	}
	if params["filename"] != "" {
		return true
	}
	// A name= parameter on the Content-Type is the pre-RFC 2183 way of saying the same
	// thing, and malware still uses it.
	if _, ctParams, err := e.Header.ContentType(); err == nil && ctParams["name"] != "" {
		return true
	}
	return !strings.HasPrefix(mediaType, "text/")
}

// classify determines the message's direction relative to the receiving organisation.
//
// With no organisation configured this is unknowable, and the fields are left null rather
// than defaulted: a wrong `type.inbound` silently changes the verdict of most of the rule
// corpus, so saying nothing is the safer failure.
func (p *parser) classify(m *mdm.MessageDataModel) {
	org := p.opts.org()
	if !org.Configured() {
		p.recordf("type", "no organisation configured, so message direction is unknown")
		return
	}

	senderInternal := false
	if m.Sender != nil {
		senderInternal = org.IsOrgAddress(m.Sender.Email)
	}

	var internalRcpt, externalRcpt bool
	for _, mb := range allRecipients(m) {
		if org.IsOrgAddress(mb.Email) {
			internalRcpt = true
		} else {
			externalRcpt = true
		}
	}

	t := &mdm.MessageType{}
	switch {
	case !senderInternal:
		// From outside the organisation to at least one address inside it.
		t.Inbound = mdm.Ptr(true)
		t.Outbound = mdm.Ptr(false)
		t.Internal = mdm.Ptr(false)
	default:
		// The sender is ours. Outbound and internal are not exclusive: a message to both a
		// colleague and a customer is both, which is why the schema has three booleans
		// rather than one enumeration.
		t.Inbound = mdm.Ptr(false)
		t.Outbound = mdm.Ptr(externalRcpt)
		t.Internal = mdm.Ptr(internalRcpt)
	}
	m.Type = t
}

func (o *Options) org() *orgconfig.Config {
	if o == nil {
		return nil
	}
	return o.Org
}

func allRecipients(m *mdm.MessageDataModel) []*mdm.Mailbox {
	if m.Recipients == nil {
		return nil
	}
	out := make([]*mdm.Mailbox, 0, len(m.Recipients.To)+len(m.Recipients.CC)+len(m.Recipients.BCC))
	out = append(out, m.Recipients.To...)
	out = append(out, m.Recipients.CC...)
	out = append(out, m.Recipients.BCC...)
	return out
}

// readLimited reads at most limit bytes, reporting an error if there was more.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(data)) > limit {
		return data[:limit], fmt.Errorf("part exceeds %d bytes and was truncated", limit)
	}
	return data, err
}

func partPath(path []int) string {
	if len(path) == 0 {
		return "body"
	}
	parts := make([]string, len(path))
	for i, n := range path {
		parts[i] = fmt.Sprint(n)
	}
	return "part " + strings.Join(parts, ".")
}
