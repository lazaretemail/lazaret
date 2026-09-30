// SPDX-License-Identifier: AGPL-3.0-only

package eml

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/lazaretemail/lazaret/mdm"
)

// Links are where most phishing actually lives, so this file is deliberately careful about
// two things the model draws out: what a link *says* versus where it *goes*, and whether a
// recipient can see it at all.

func htmlLinks(h *mdm.BodyHTML) []*mdm.Link {
	if h == nil {
		return nil
	}
	return h.Links
}

func plainLinks(p *mdm.Plain) []*mdm.Link {
	if p == nil {
		return nil
	}
	return p.Links
}

// linksFromHTML collects anchors and other URL-bearing elements from a parsed document.
func linksFromHTML(doc *html.Node) []*mdm.Link {
	var out []*mdm.Link

	var walk func(n *html.Node, hidden bool)
	walk = func(n *html.Node, hidden bool) {
		if n.Type == html.ElementNode {
			if isHidden(n) {
				hidden = true
			}
			switch n.DataAtom {
			case atom.Script, atom.Style:
				return
			case atom.A, atom.Area:
				if l := anchorLink(n, hidden); l != nil {
					out = append(out, l)
				}
			case atom.Form:
				// A form posting to an external endpoint is a credential-harvesting
				// pattern, and its action is a link in every sense that matters.
				if href := attr(n, "action"); href != "" {
					if l := buildLink(href, "", hidden, mdm.LinkParserHyperlink); l != nil {
						out = append(out, l)
					}
				}
			case atom.Iframe, atom.Frame, atom.Embed:
				if src := attr(n, "src"); src != "" {
					if l := buildLink(src, "", hidden, mdm.LinkParserHyperlink); l != nil {
						out = append(out, l)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, hidden)
		}
	}
	walk(doc, false)

	// Bare URLs typed into the body are links too, and mail clients render them as such.
	out = append(out, linksFromText(innerText(doc, false))...)
	return dedupeLinks(out)
}

func anchorLink(n *html.Node, hidden bool) *mdm.Link {
	href := strings.TrimSpace(attr(n, "href"))
	if href == "" || strings.HasPrefix(href, "#") {
		return nil
	}
	text := normaliseWhitespace(innerText(n, false))
	return buildLink(href, text, hidden, mdm.LinkParserHyperlink)
}

// buildLink constructs a Link, including the mismatch signal.
func buildLink(href, displayText string, hidden bool, parser mdm.LinkParser) *mdm.Link {
	target := mdm.ParseURL(href, false)
	if target == nil {
		return nil
	}

	l := &mdm.Link{
		HrefURL: target,
		Parser:  &parser,
		Visible: mdm.Ptr(!hidden),
	}
	if displayText != "" {
		l.DisplayText = mdm.Ptr(displayText)
	}

	// When the visible text is itself a URL, the gap between what it claims and where the
	// link goes is the classic deceptive-link pattern. When the text is ordinary prose
	// there is nothing to compare, and the field stays null rather than false — claiming
	// "not mismatched" would be a finding we have not actually made.
	if displayText != "" && looksLikeURL(displayText) {
		shown := mdm.ParseURL(displayText, false)
		l.DisplayURL = shown
		l.Mismatched = mdm.Ptr(!sameTarget(shown, target))
	}
	return l
}

// sameTarget compares two URLs by registrable domain. Comparing the full string would flag
// every tracking parameter and shortened form as deceptive; the registrable domain is the
// level at which "this is not where it says it goes" is actually true.
func sameTarget(shown, target *mdm.URL) bool {
	if shown == nil || target == nil {
		return false
	}
	sd, td := shown.Domain, target.Domain
	if sd == nil || td == nil {
		return shown.URL == target.URL
	}
	if sd.RootDomain != nil && td.RootDomain != nil {
		return *sd.RootDomain == *td.RootDomain
	}
	return sd.Domain == td.Domain
}

// urlPattern finds bare URLs in plain text. It deliberately does not try to be a complete
// URL grammar: it looks for the shapes that appear in mail and lets ParseURL reject the
// rest.
var urlPattern = regexp.MustCompile(`(?i)\b(?:(?:https?|ftp|mailto|tel)://[^\s<>"'` + "`" + `\)\]]+|mailto:[^\s<>"']+|www\.[^\s<>"'` + "`" + `\)\]]+)`)

func linksFromText(text string) []*mdm.Link {
	if text == "" {
		return nil
	}
	var out []*mdm.Link
	for _, raw := range urlPattern.FindAllString(text, -1) {
		// Trailing punctuation belongs to the sentence, not the URL.
		raw = strings.TrimRight(raw, ".,;:!?")
		if l := buildLink(raw, "", false, mdm.LinkParserPlain); l != nil {
			out = append(out, l)
		}
	}
	return dedupeLinks(out)
}

func extractURLsFromText(text string) []*mdm.URL {
	var out []*mdm.URL
	for _, raw := range urlPattern.FindAllString(text, -1) {
		if u := mdm.ParseURL(strings.TrimRight(raw, ".,;:!?"), false); u != nil {
			out = append(out, u)
		}
	}
	return out
}

func looksLikeURL(s string) bool {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, " \t\n") {
		return false
	}
	return urlPattern.MatchString(s) || mdm.ParseDomain(s) != nil && strings.Contains(s, ".")
}

// mergeLinks combines link sets, keeping the first occurrence of each distinct
// target-and-text pair. The schema says body.links is unique by target and display text,
// which matters because a template repeating the same call-to-action ten times should not
// look like ten separate lures.
func mergeLinks(sets ...[]*mdm.Link) []*mdm.Link {
	var all []*mdm.Link
	for _, s := range sets {
		all = append(all, s...)
	}
	return dedupeLinks(all)
}

func dedupeLinks(links []*mdm.Link) []*mdm.Link {
	if len(links) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(links))
	out := make([]*mdm.Link, 0, len(links))
	for _, l := range links {
		if l == nil || l.HrefURL == nil {
			continue
		}
		key := l.HrefURL.URL + "\x00" + mdm.Deref(l.DisplayText)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, l)
	}
	return out
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

// ipsFromText finds addresses written into the body. A raw address in an otherwise
// branded message is a signal in its own right.
func ipsFromText(text string) []*mdm.IP {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []*mdm.IP
	for _, m := range ipPattern.FindAllStringSubmatch(text, -1) {
		ip := parseIP(m[1])
		if ip == nil || seen[ip.IP] {
			continue
		}
		seen[ip.IP] = true
		out = append(out, ip)
	}
	return out
}
