// SPDX-License-Identifier: AGPL-3.0-only

package eml

import (
	"net/mail"
	"regexp"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-msgauth/authres"

	"github.com/lazaretemail/lazaret/mdm"
)

// parseHops reconstructs the message's delivery path.
//
// Each hop is one Received header plus whatever other trace headers were added at the same
// point. Hop 0 is the most recent — the MTA closest to the recipient — because that is the
// one whose word can be trusted furthest: everything below it was written by a server the
// receiving organisation does not control, and an attacker can forge as much of the lower
// path as they like.
//
// Rules lean on this heavily: `any(headers.hops, .index == 0 and ...)` is the idiom for
// "what did our own infrastructure say about this message".
func (p *parser) parseHops(hdr *mdm.Headers, h message.Header) {
	// Walk the header block in order, grouping trace headers under the Received line they
	// follow. Received headers are prepended by each MTA, so document order is already
	// newest-first.
	var hops []*mdm.Hop
	var current *mdm.Hop
	position := int64(0)

	fields := h.Fields()
	for fields.Next() {
		key := strings.ToLower(fields.Key())
		value, err := fields.Text()
		if err != nil {
			value = fields.Value()
		}
		value = strings.TrimSpace(value)

		if key == "received" {
			current = &mdm.Hop{Index: int64(len(hops)), Received: parseReceived(value)}
			hops = append(hops, current)
			position = 0
		}
		if current == nil {
			// Headers above the first Received line belong to the message, not to any hop.
			continue
		}

		current.Fields = append(current.Fields, &mdm.HopField{
			Name:     fields.Key(),
			Position: position,
			Value:    mdm.Ptr(value),
		})
		position++

		switch key {
		case "authentication-results", "arc-authentication-results":
			if res := p.parseAuthResults(value); res != nil {
				current.AuthenticationResults = res
			}
		case "received-spf":
			current.ReceivedSPF = parseReceivedSPF(value)
		case "dkim-signature", "arc-message-signature":
			current.Signature = parseSignature(value)
		}
	}

	hdr.Hops = hops
}

// receivedClause splits a Received header into its RFC 5321 clauses. The grammar is widely
// ignored in practice, so each clause is captured raw rather than parsed further: rules
// match on the text, and inventing structure that is not really there would be worse than
// exposing what the MTA actually wrote.
var receivedClause = regexp.MustCompile(`(?is)\b(from|by|via|with|id|for)\s+(.*?)(?:\s+(?:from|by|via|with|id|for)\s|$)`)

func parseReceived(value string) *mdm.Received {
	r := &mdm.Received{}

	// The timestamp follows the final semicolon.
	body := value
	if semi := strings.LastIndex(value, ";"); semi >= 0 {
		body = value[:semi]
		stamp := strings.TrimSpace(value[semi+1:])
		if t, err := mail.ParseDate(stamp); err == nil {
			utc := t.UTC()
			r.Time = &utc
			_, offset := t.Zone()
			r.ZoneOffset = mdm.Ptr(formatOffset(offset))
		}
	}

	// Scan clauses left to right. The regexp is applied repeatedly from the last match so
	// that adjacent clauses are not swallowed by the non-greedy body.
	rest := body
	for {
		m := receivedClause.FindStringSubmatchIndex(rest)
		if m == nil {
			break
		}
		keyword := strings.ToLower(rest[m[2]:m[3]])
		text := strings.TrimSpace(rest[m[4]:m[5]])
		raw := mdm.Ptr(text)

		switch keyword {
		case "from":
			r.Source = &mdm.ReceivedFrom{Raw: raw}
		case "by":
			r.Server = &mdm.ReceivedBy{Raw: raw}
		case "via":
			r.Link = &mdm.ReceivedVia{Raw: raw}
		case "with":
			r.Protocol = &mdm.ReceivedWith{Raw: raw}
		case "id":
			r.ID = &mdm.ReceivedID{Raw: raw}
		case "for":
			r.Mailbox = &mdm.ReceivedFor{Raw: raw}
		}

		// Resume just before the next keyword, which the match consumed as a delimiter.
		next := m[5]
		if next >= len(rest) {
			break
		}
		rest = rest[next:]
	}

	if r.Source == nil && r.Server == nil && strings.TrimSpace(body) != "" {
		r.Additional = &mdm.ReceivedAdditional{Raw: mdm.Ptr(strings.TrimSpace(body))}
	}
	return r
}

// parseReceivedSPF reads a Received-SPF header, which records what the receiving MTA
// concluded before any Authentication-Results line was written.
func parseReceivedSPF(value string) *mdm.SPF {
	s := &mdm.SPF{}

	verdict, rest, _ := strings.Cut(strings.TrimSpace(value), " ")
	if verdict != "" {
		v := strings.ToLower(strings.TrimSpace(verdict))
		s.Verdict = mdm.Ptr(v)
	}
	if desc := strings.TrimSpace(rest); desc != "" {
		s.Description = mdm.Ptr(desc)
	}

	for k, v := range keyValues(rest) {
		switch k {
		case "client-ip":
			s.ClientIP = parseIP(v)
		case "helo":
			s.Helo = mdm.ParseDomain(v)
		case "envelope-from", "envelope-sender":
			if addr := mdm.ParseEmailAddress(v); addr != nil && addr.Email != nil {
				s.Designator = addr.Email
			}
		case "receiver":
			s.Server = mdm.ParseDomain(v)
		}
	}
	return s
}

// signatureTag reads the tag=value pairs of a DKIM-Signature.
var signatureTag = regexp.MustCompile(`(?s)([a-zA-Z]+)\s*=\s*([^;]*)`)

func parseSignature(value string) *mdm.Signature {
	sig := &mdm.Signature{}
	for _, m := range signatureTag.FindAllStringSubmatch(value, -1) {
		v := strings.TrimSpace(strings.Join(strings.Fields(m[2]), ""))
		switch strings.ToLower(m[1]) {
		case "v":
			sig.Version = mdm.Ptr(v)
		case "a":
			sig.Algorithm = mdm.Ptr(v)
		case "d":
			sig.Domain = mdm.Ptr(strings.ToLower(v))
		case "s":
			sig.Selector = mdm.Ptr(v)
		case "bh":
			sig.BodyHash = mdm.Ptr(v)
		case "b":
			sig.Signature = mdm.Ptr(v)
		case "i":
			sig.Instance = mdm.Ptr(v)
		case "h":
			// The signed-header list, as written. Rules match on it with patterns such as
			// ilike "*:reply-to" to spot a signature that does not cover the reply address.
			sig.Headers = mdm.Ptr(strings.ToLower(v))
		}
	}
	if sig.Domain == nil && sig.Selector == nil && sig.Signature == nil {
		return nil
	}
	sig.Type = mdm.Ptr("dkim")
	return sig
}

// parseAuthResults reads an Authentication-Results header.
//
// This is the receiving MTA's own verdict on SPF, DKIM and DMARC. The engine trusts it
// rather than re-verifying: re-running SPF needs DNS, and re-running DKIM against a message
// the MTA may have modified in transit would disagree with the MTA for reasons that have
// nothing to do with the sender. Real verification is available behind an interface for a
// later module that wants ground truth instead.
func (p *parser) parseAuthResults(value string) *mdm.AuthResults {
	identifier, results, err := authres.Parse(value)
	if err != nil {
		// These headers are frequently non-conforming. Salvage what a regexp can see
		// rather than dropping the MTA's verdict entirely.
		if res := looseAuthResults(value); res != nil {
			return res
		}
		p.recordf("authentication-results", "%v", err)
		return nil
	}

	out := &mdm.AuthResults{Type: mdm.Ptr("authentication-results")}
	if identifier != "" {
		out.Server = mdm.ParseDomain(identifier)
	}

	for _, r := range results {
		switch v := r.(type) {
		case *authres.SPFResult:
			out.SPF = mdm.Ptr(mdm.AuthResultsSPF(strings.ToLower(string(v.Value))))
			d := &mdm.SPF{Verdict: mdm.Ptr(strings.ToLower(string(v.Value)))}
			if v.From != "" {
				d.Designator = mdm.Ptr(strings.ToLower(v.From))
			}
			if v.Helo != "" {
				d.Helo = mdm.ParseDomain(v.Helo)
			}
			if v.Reason != "" {
				d.Description = mdm.Ptr(v.Reason)
			}
			out.SPFDetails = d

		case *authres.DKIMResult:
			out.DKIM = mdm.Ptr(mdm.AuthResultsDKIM(strings.ToLower(string(v.Value))))
			sig := &mdm.Signature{Type: mdm.Ptr("dkim")}
			if v.Domain != "" {
				sig.Domain = mdm.Ptr(strings.ToLower(v.Domain))
			}
			if v.Identifier != "" {
				sig.Instance = mdm.Ptr(v.Identifier)
			}
			out.DKIMDetails = append(out.DKIMDetails, sig)

		case *authres.DMARCResult:
			out.DMARC = mdm.Ptr(mdm.AuthResultsDMARC(strings.ToLower(string(v.Value))))
			d := &mdm.DMARC{Verdict: mdm.Ptr(strings.ToLower(string(v.Value)))}
			if v.From != "" {
				d.From = mdm.ParseDomain(v.From)
			}
			out.DMARCDetails = d

		case *authres.AuthResult:
			// Nothing in the model for SMTP AUTH; the raw field is still on the hop.
		}
	}

	// compauth is Microsoft's composite verdict. It is not in the RFC, so it has to be
	// read out of the raw text, and rules do use it.
	if kv := keyValues(value); kv["compauth"] != "" {
		out.Compauth = &mdm.CompAuth{
			Verdict: strings.ToLower(kv["compauth"]),
			Reason:  kv["reason"],
		}
	}
	return out
}

var looseAuthMethod = regexp.MustCompile(`(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z]+)`)

func looseAuthResults(value string) *mdm.AuthResults {
	matches := looseAuthMethod.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil
	}
	out := &mdm.AuthResults{Type: mdm.Ptr("authentication-results")}
	for _, m := range matches {
		verdict := strings.ToLower(m[2])
		switch strings.ToLower(m[1]) {
		case "spf":
			out.SPF = mdm.Ptr(mdm.AuthResultsSPF(verdict))
			out.SPFDetails = &mdm.SPF{Verdict: mdm.Ptr(verdict)}
		case "dkim":
			out.DKIM = mdm.Ptr(mdm.AuthResultsDKIM(verdict))
		case "dmarc":
			out.DMARC = mdm.Ptr(mdm.AuthResultsDMARC(verdict))
			out.DMARCDetails = &mdm.DMARC{Verdict: mdm.Ptr(verdict)}
		}
	}
	return out
}

// summariseAuth reduces the per-hop authentication results to the single verdict rules
// actually ask for: headers.auth_summary.dmarc.pass, used 609 times in the public corpus.
//
// The summary comes from the *most recent* hop that reported a verdict — the one closest to
// the recipient, written by infrastructure the organisation controls. Taking the earliest,
// or merging them, would let an attacker inject a favourable Authentication-Results header
// further down the path and have it believed.
func (p *parser) summariseAuth(hdr *mdm.Headers) {
	summary := &mdm.AuthSummary{}
	hdr.AuthSummary = summary

	for _, hop := range hdr.Hops {
		res := hop.AuthenticationResults

		if summary.SPF == nil {
			switch {
			case res != nil && res.SPF != nil:
				verdict := string(*res.SPF)
				summary.SPF = &mdm.SPFSummary{
					Pass:        mdm.Ptr(verdict == "pass"),
					Error:       mdm.Ptr(verdict == "temperror" || verdict == "permerror"),
					Details:     res.SPFDetails,
					ReceivedHop: mdm.Ptr(hop.Index),
				}
			case hop.ReceivedSPF != nil && hop.ReceivedSPF.Verdict != nil:
				verdict := *hop.ReceivedSPF.Verdict
				summary.SPF = &mdm.SPFSummary{
					Pass:        mdm.Ptr(verdict == "pass"),
					Error:       mdm.Ptr(verdict == "temperror" || verdict == "permerror"),
					Details:     hop.ReceivedSPF,
					ReceivedHop: mdm.Ptr(hop.Index),
				}
			}
		}

		if summary.DMARC == nil && res != nil && res.DMARC != nil {
			verdict := string(*res.DMARC)
			summary.DMARC = &mdm.DMARCSummary{
				// "bestguesspass" is a heuristic pass used when the domain publishes no
				// DMARC record. It is not a real pass, and treating it as one would let
				// any domain without a policy inherit the trust of one that has it.
				Pass:        mdm.Ptr(verdict == "pass"),
				Error:       mdm.Ptr(verdict == "temperror" || verdict == "permerror"),
				Details:     res.DMARCDetails,
				ReceivedHop: mdm.Ptr(hop.Index),
			}
		}
	}
}

// keyValues pulls `key=value` pairs out of free-form header text, honouring quotes and
// stopping values at whitespace, semicolons or commas.
func keyValues(s string) map[string]string {
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9_.-]*)\s*=\s*("([^"]*)"|[^\s;,]+)`).FindAllStringSubmatch(s, -1) {
		value := m[2]
		if m[3] != "" || strings.HasPrefix(value, `"`) {
			value = m[3]
		}
		key := strings.ToLower(m[1])
		if _, seen := out[key]; !seen {
			out[key] = value
		}
	}
	return out
}
