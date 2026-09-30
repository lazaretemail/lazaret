// SPDX-License-Identifier: AGPL-3.0-only

package rdap

import "github.com/lazaretemail/lazaret/mdm"

// Exposed to the external test package so the legacy WHOIS parser can be exercised
// against captured registry output without opening a socket. The parser is the part of
// the fallback worth testing; the socket is not.

// ParseLegacyForTest parses raw WHOIS text into the model.
func (c *Client) ParseLegacyForTest(name, text string) *mdm.WhoisOutput {
	return c.parseLegacy(name, text)
}

// ReservedTLDForTest exposes the reserved-TLD check to the package's tests.
func ReservedTLDForTest(name string) bool { return reservedTLD(name) }
