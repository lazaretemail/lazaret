// SPDX-License-Identifier: AGPL-3.0-only

package eml

import (
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/lazaretemail/lazaret/mdm"
)

// buildBody assembles the message body from the text parts collected during the MIME walk.
func (p *parser) buildBody(m *mdm.MessageDataModel) {
	body := &mdm.Body{}
	m.Body = body

	if len(p.plain) > 0 {
		joined := joinParts(p.plain)
		plain := &mdm.Plain{Raw: mdm.Ptr(joined)}
		if c := p.plain[0].charset; c != "" {
			plain.Charset = mdm.Ptr(strings.ToLower(c))
		}
		if e := p.plain[0].encoding; e != "" {
			plain.ContentTransferEncoding = mdm.Ptr(strings.ToLower(e))
		}
		plain.Links = linksFromText(joined)
		body.Plain = plain
	}

	if len(p.html) > 0 {
		raw := joinParts(p.html)
		h := &mdm.BodyHTML{Raw: mdm.Ptr(raw)}
		if c := p.html[0].charset; c != "" {
			h.Charset = mdm.Ptr(strings.ToLower(c))
		}
		if e := p.html[0].encoding; e != "" {
			h.ContentTransferEncoding = mdm.Ptr(strings.ToLower(e))
		}

		doc, err := html.Parse(strings.NewReader(raw))
		if err != nil {
			p.recordf("body.html", "%v", err)
		} else {
			h.InnerText = mdm.Ptr(innerText(doc, false))
			h.DisplayText = mdm.Ptr(innerText(doc, true))
			h.Links = linksFromHTML(doc)
		}
		body.HTML = h
	}

	body.Links = mergeLinks(htmlLinks(body.HTML), plainLinks(body.Plain))
	body.IPs = ipsFromText(bodyText(body))

	p.buildThreads(m, body)
}

func joinParts(parts []textPart) string {
	if len(parts) == 1 {
		return parts[0].text
	}
	var b strings.Builder
	for i, part := range parts {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(part.text)
	}
	return b.String()
}

// bodyText returns the most readable form of the body, preferring the rendered HTML text
// over the plain alternative. Rules reach for body.current_thread.text, which is derived
// from this.
func bodyText(body *mdm.Body) string {
	if body.HTML != nil && body.HTML.InnerText != nil && strings.TrimSpace(*body.HTML.InnerText) != "" {
		return *body.HTML.InnerText
	}
	if body.Plain != nil && body.Plain.Raw != nil {
		return *body.Plain.Raw
	}
	return ""
}

// hiddenStyle matches the inline styles used to hide text from a reader while leaving it in
// the document — a standard trick for defeating keyword matching, and the reason
// display_text and inner_text are separate fields.
func isHidden(n *html.Node) bool {
	for _, a := range n.Attr {
		switch strings.ToLower(a.Key) {
		case "hidden":
			return true
		case "style":
			s := strings.ToLower(strings.ReplaceAll(a.Val, " ", ""))
			if strings.Contains(s, "display:none") ||
				strings.Contains(s, "visibility:hidden") ||
				strings.Contains(s, "font-size:0") ||
				strings.Contains(s, "opacity:0") ||
				strings.Contains(s, "max-height:0") {
				return true
			}
		}
	}
	return false
}

// innerText extracts the text of a document.
//
// With visibleOnly set it skips content a recipient cannot see, giving display_text; with
// it clear everything is included, giving inner_text. Attackers rely on the gap between
// the two — hidden keyword stuffing to poison classifiers, zero-height text to break
// phrase matching — so both are kept and rules can compare them.
func innerText(n *html.Node, visibleOnly bool) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			b.WriteString(n.Data)
			return
		case html.ElementNode:
			switch n.DataAtom {
			case atom.Script, atom.Style, atom.Head, atom.Title, atom.Noscript:
				// Never readable content, in either form.
				return
			}
			if visibleOnly && isHidden(n) {
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
		if n.Type == html.ElementNode {
			switch n.DataAtom {
			case atom.P, atom.Div, atom.Br, atom.Tr, atom.Li, atom.Table,
				atom.H1, atom.H2, atom.H3, atom.H4, atom.H5, atom.H6:
				b.WriteString("\n")
			case atom.Td, atom.Th:
				b.WriteString(" ")
			}
		}
	}
	walk(n)
	return normaliseWhitespace(b.String())
}

// normaliseWhitespace collapses the runs of blank lines and spaces that HTML-to-text
// conversion produces, without destroying paragraph structure — rules match on phrases
// that span what the author intended as one line.
func normaliseWhitespace(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	blank := 0
	for _, line := range lines {
		line = strings.TrimSpace(strings.Join(strings.Fields(line), " "))
		if line == "" {
			blank++
			if blank > 1 {
				continue
			}
		} else {
			blank = 0
		}
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}
