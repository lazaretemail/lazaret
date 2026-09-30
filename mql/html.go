// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"strings"

	"github.com/antchfx/htmlquery"
	"golang.org/x/net/html"

	"github.com/lazaretemail/lazaret/mdm"
)

// HTML handling for the pure functions: html.xpath, strings.parse_html and
// file.parse_html.
//
// Rules reach for XPath when a pattern is structural rather than textual — "an anchor
// whose text is an image", "a form posting off-site" — which regular expressions over
// markup cannot express without being wrong in interesting ways.

// htmlSource pulls markup out of whatever a rule passed in: a body part, an already
// parsed document, a file, or a bare string.
func htmlSource(v Value) (string, bool) {
	if s, ok := v.AsString(); ok {
		return s, true
	}
	for _, field := range []string{"raw", "text"} {
		if inner := v.Field(field); !inner.IsNull() {
			if s, ok := inner.AsString(); ok {
				return s, true
			}
		}
	}
	return "", false
}

// parseHTMLValue builds the HTML object that strings.parse_html and file.parse_html
// return.
func parseHTMLValue(v Value) Value {
	src, ok := htmlSource(v)
	if !ok {
		return NullValue
	}
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		return NullValue
	}
	return FromGo(&mdm.HTML{
		Raw:         mdm.Ptr(src),
		InnerText:   mdm.Ptr(nodeText(doc, false)),
		DisplayText: mdm.Ptr(nodeText(doc, true)),
	})
}

// xpathQuery runs an XPath expression over a document.
//
// A malformed expression is an error rather than null: unlike a field that happens to be
// absent, a query that cannot be compiled is a mistake in the rule, and returning null
// would let it sit there matching nothing forever.
func xpathQuery(input Value, query string) (Value, error) {
	src, ok := htmlSource(input)
	if !ok {
		return NullValue, nil
	}
	doc, err := htmlquery.Parse(strings.NewReader(src))
	if err != nil {
		return NullValue, nil
	}

	nodes, err := htmlquery.QueryAll(doc, query)
	if err != nil {
		return NullValue, err
	}

	out := make([]*mdm.HTMLNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, &mdm.HTMLNode{
			Raw:         mdm.Ptr(htmlquery.OutputHTML(n, true)),
			InnerText:   mdm.Ptr(strings.TrimSpace(nodeText(n, false))),
			DisplayText: mdm.Ptr(strings.TrimSpace(nodeText(n, true))),
			Links:       nodeLinks(n),
		})
	}
	return FromGo(&mdm.HTMLXPathResult{Nodes: out}), nil
}

// nodeText renders an element's text. With visibleOnly set it skips content a recipient
// cannot see, which is the same distinction the message parser draws for the body.
func nodeText(n *html.Node, visibleOnly bool) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			b.WriteString(n.Data)
			return
		case html.ElementNode:
			switch strings.ToLower(n.Data) {
			case "script", "style", "head", "title", "noscript":
				return
			}
			if visibleOnly && hiddenByStyle(n) {
				return
			}
		case html.CommentNode, html.DoctypeNode:
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "p", "div", "br", "tr", "li", "table", "h1", "h2", "h3", "h4", "h5", "h6":
				b.WriteString("\n")
			case "td", "th":
				b.WriteString(" ")
			}
		}
	}
	walk(n)

	lines := strings.Split(b.String(), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if line = strings.Join(strings.Fields(line), " "); line != "" {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func hiddenByStyle(n *html.Node) bool {
	for _, a := range n.Attr {
		switch strings.ToLower(a.Key) {
		case "hidden":
			return true
		case "style":
			s := strings.ToLower(strings.ReplaceAll(a.Val, " ", ""))
			if strings.Contains(s, "display:none") || strings.Contains(s, "visibility:hidden") ||
				strings.Contains(s, "font-size:0") || strings.Contains(s, "opacity:0") {
				return true
			}
		}
	}
	return false
}

// nodeLinks collects the anchors inside a matched element, so a rule can select a
// container and then inspect what it points at.
func nodeLinks(n *html.Node) []*mdm.Link {
	var out []*mdm.Link
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "a") {
			for _, a := range n.Attr {
				if !strings.EqualFold(a.Key, "href") {
					continue
				}
				if u := mdm.ParseURL(strings.TrimSpace(a.Val), false); u != nil {
					link := &mdm.Link{HrefURL: u}
					if text := strings.TrimSpace(nodeText(n, false)); text != "" {
						link.DisplayText = mdm.Ptr(text)
					}
					out = append(out, link)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return out
}

// ParseHTML parses a document into the model's HTML type.
//
// Exported for services that hold HTML which did not come from a message — the render
// client turns a fetched page into ml.link_analysis's final_dom this way. It is the same
// code path as strings.parse_html, deliberately: a rule reading .inner_text off a
// fetched page and off an attachment should get text extracted the same way, or the two
// halves of a rule disagree about what the words were.
func ParseHTML(src string) *mdm.HTML {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		return nil
	}
	return &mdm.HTML{
		Raw:         mdm.Ptr(src),
		InnerText:   mdm.Ptr(nodeText(doc, false)),
		DisplayText: mdm.Ptr(nodeText(doc, true)),
	}
}
