// SPDX-License-Identifier: AGPL-3.0-only

package sensitive

import (
	"context"
	"strings"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// Enricher answers beta.ml_extract_sensitive_information.
//
// It needs no service and no model, so unlike the other capabilities in the ml.*
// namespace it is registered in-process. A deployment gets DLP by configuring nothing.
type Enricher struct{}

// New returns an Enricher.
func New() *Enricher { return &Enricher{} }

// Capabilities are what this answers, for registering with an mql.MuxEnricher.
func Capabilities() []enrich.Capability {
	return []enrich.Capability{enrich.CapBetaExtractPII}
}

// Enrich implements mql.Enricher.
func (e *Enricher) Enrich(_ context.Context, cap enrich.Capability, args []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	if cap != enrich.CapBetaExtractPII {
		return mql.NullValue, enrich.NotImplemented(cap)
	}
	if len(args) == 0 {
		return mql.NullValue, nil
	}

	text := textOf(args[0])
	if text == "" {
		return mql.NullValue, nil
	}

	found := Extract(text)
	out := &mdm.SensitiveInfoOutput{}
	for _, f := range found {
		out.Elements = append(out.Elements, &mdm.SensitiveElement{
			Type:       mdm.Ptr(f.Type),
			Value:      mdm.Ptr(f.Value),
			Confidence: mdm.Ptr(f.Confidence),
			Score:      mdm.Ptr(f.Score),
		})
	}
	// An empty elements list is a real answer — this message discloses nothing — and
	// must not be null, or every DLP rule reports indeterminate on clean mail.
	return mql.FromGo(out), nil
}

// textOf pulls text out of whatever a rule passed.
//
// The corpus calls this on a message, on body text, and on an attachment's content. All
// three are the same question — what words are in this thing — so all three are
// accepted rather than requiring the rule to be written one particular way.
func textOf(v mql.Value) string {
	if s, ok := v.AsString(); ok && s != "" {
		return s
	}
	if b, ok := v.AsBytes(); ok && len(b) > 0 {
		return string(b)
	}

	var parts []string
	add := func(s string) {
		if s != "" {
			parts = append(parts, s)
		}
	}

	// A message: body text, subject, and any attachment that is already text. All of it,
	// because a card number pasted into a footer discloses just as much as one in the
	// first line.
	body := v.Field("body")
	add(str(body.Field("current_thread").Field("text")))
	add(str(body.Field("plain").Field("raw")))
	add(str(body.Field("html").Field("inner_text")))
	add(str(v.Field("subject").Field("subject")))

	// A file or an attachment.
	add(str(v.Field("text")))
	add(str(v.Field("inner_text")))
	add(str(v.Field("raw")))

	return strings.Join(parts, "\n")
}

func str(v mql.Value) string {
	if s, ok := v.AsString(); ok {
		return s
	}
	if b, ok := v.AsBytes(); ok {
		return string(b)
	}
	return ""
}
