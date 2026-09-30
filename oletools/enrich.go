// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import (
	"context"

	"github.com/lazaretemail/lazaret/enrich"

	"github.com/lazaretemail/lazaret/mql"
)

// The MQL seam.
//
// Local, like sensitive and unlike strelka: there is no service to reach, so this
// answers on a deployment with nothing else configured, and in the CLI.

// Capabilities are what this package answers, for registering with an mql.MuxEnricher.
func Capabilities() []enrich.Capability {
	return []enrich.Capability{enrich.CapFileOletools}
}

// Client answers file.oletools.
type Client struct {
	Analyzer Analyzer
}

// New returns a client with the default limits.
func New() *Client { return &Client{} }

// Enrich implements mql.Enricher.
func (c *Client) Enrich(ctx context.Context, cap enrich.Capability, args []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	if cap != enrich.CapFileOletools {
		return mql.NullValue, enrich.NotImplemented(cap)
	}
	if len(args) == 0 {
		return mql.NullValue, nil
	}

	raw, ok := fileBytes(args[0])
	if !ok || len(raw) == 0 {
		// A call on something with no content is not a failure and not a
		// document; null says "nothing to say about this".
		return mql.NullValue, nil
	}
	if err := ctx.Err(); err != nil {
		return mql.NullValue, &enrich.Unavailable{
			Capability: cap, Reason: "analysis deadline reached", Err: err,
		}
	}

	return mql.FromGo(c.Analyzer.Analyze(raw)), nil
}

// fileBytes pulls the content out of whatever the rule passed. The corpus idiom is
// `file.oletools(.)` inside `any(attachments, ...)`, so the argument is an
// Attachment or a File; a bare byte string is accepted too.
func fileBytes(v mql.Value) ([]byte, bool) {
	for _, field := range []string{"raw", "data", "content"} {
		if b, ok := v.Field(field).AsBytes(); ok && len(b) > 0 {
			return b, true
		}
	}
	if b, ok := v.AsBytes(); ok && len(b) > 0 {
		return b, true
	}
	return nil, false
}
