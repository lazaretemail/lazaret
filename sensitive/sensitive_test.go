// SPDX-License-Identifier: AGPL-3.0-only

package sensitive_test

import (
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/sensitive"
)

func find(t *testing.T, text, want string) sensitive.Element {
	t.Helper()
	for _, e := range sensitive.Extract(text) {
		if e.Type == want {
			return e
		}
	}
	t.Fatalf("no %s found in %q; got %v", want, text, sensitive.Extract(text))
	return sensitive.Element{}
}

func absent(t *testing.T, text, unwanted string) {
	t.Helper()
	for _, e := range sensitive.Extract(text) {
		if e.Type == unwanted {
			t.Errorf("%s reported for %q (value %q)", unwanted, text, e.Value)
		}
	}
}

// A failed checksum is not a low-confidence finding, it is not a finding. This is the
// property that keeps a DLP tool switched on.
func TestChecksumsRejectNearMisses(t *testing.T) {
	// 4111 1111 1111 1111 is the canonical Luhn-valid test card; changing one digit
	// leaves the shape intact and the checksum wrong.
	find(t, "card 4111 1111 1111 1111 on file", "credit_card_number")
	absent(t, "card 4111 1111 1111 1112 on file", "credit_card_number")

	find(t, "IBAN GB82 WEST 1234 5698 7654 32", "iban_code")
	absent(t, "IBAN GB82 WEST 1234 5698 7654 33", "iban_code")

	find(t, "NHS 943 476 5919", "nhs_number")
	absent(t, "NHS 943 476 5918", "nhs_number")

	find(t, "BSN 111222333", "nl_bsn")
	absent(t, "BSN 111222334", "nl_bsn")
}

func TestHighConfidenceOnlyAfterAChecksum(t *testing.T) {
	e := find(t, "4111 1111 1111 1111", "credit_card_number")
	if e.Confidence != sensitive.High {
		t.Errorf("confidence = %q, want high after a passing checksum", e.Confidence)
	}

	// A BIC has no checksum. Reporting it as high would let a rule keyed on
	// `.confidence == "high"` fire on an ordinary eight-letter word.
	e = find(t, "swift DEUTDEFF today", "swift_bic")
	if e.Confidence == sensitive.High {
		t.Error("swift_bic claims high confidence with nothing to verify it")
	}
}

// The ranges the SSA never issues are what stop a formatted date reading as an SSN.
func TestSSNRejectsNeverIssuedRanges(t *testing.T) {
	find(t, "SSN 123-45-6789", "social_security_number")
	for _, bad := range []string{"000-45-6789", "666-45-6789", "900-45-6789", "123-00-6789", "123-45-0000"} {
		absent(t, "SSN "+bad, "social_security_number")
	}
}

// A nine-digit number is a routing number, an employee id, or a part number. Without the
// Federal Reserve district check every coincidental checksum becomes a bank account.
func TestABARejectsUnassignedDistricts(t *testing.T) {
	find(t, "routing 021000021", "us_aba_routing_number")
	absent(t, "part 130000017", "us_aba_routing_number")
}

func TestSecretsAreFoundOnShape(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"AKIAIOSFODNN7EXAMPLE", "aws_access_key"},
		{"ghp_1234567890abcdefghijklmnopqrstuvwxyz", "github_token"},
		{"AIzaSyD-1234567890abcdefghijklmnopqrstu", "google_api_key"},
		{"xoxb-123456789012-abcdefghijklmnopqrst", "slack_access_token"},
		{"-----BEGIN RSA PRIVATE KEY-----", "private_key"},
		{"-----BEGIN CERTIFICATE-----", "ssl_certificate"},
		{"Authorization: Bearer abcdef0123456789", "http_authorization_header"},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", "jwt"},
		{"wallet 0x52908400098527886E0F7030069857D2E4169EE7", "crypto_wallet_address"},
		{"mac 00:1B:44:11:3A:B7", "mac_address"},
	} {
		e := find(t, "text "+tc.text+" more", tc.want)
		if e.Value == "" {
			t.Errorf("%s matched with an empty value", tc.want)
		}
	}
}

func TestVINChecksum(t *testing.T) {
	find(t, "VIN 1M8GDM9AXKP042788", "vehicle_vin")
	absent(t, "VIN 1M8GDM9AXKP042789", "vehicle_vin")
}

// A value appearing in both the HTML and plain-text parts of a message is one
// disclosure, not two, and a rule counting elements should not double it.
func TestFindingsAreDeduplicated(t *testing.T) {
	text := "card 4111 1111 1111 1111 ... and again card 4111 1111 1111 1111"
	n := 0
	for _, e := range sensitive.Extract(text) {
		if e.Type == "credit_card_number" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d card findings, want 1", n)
	}
}

func TestEmptyInputFindsNothing(t *testing.T) {
	if got := sensitive.Extract("   \n\t "); len(got) != 0 {
		t.Errorf("found %v in whitespace", got)
	}
}

func TestOrdinaryProseIsClean(t *testing.T) {
	prose := `Hi team, please review the Q3 numbers before Friday. The meeting is at
	14:00 in room 4 and we expect about 120 attendees. Regards, Sam`
	if got := sensitive.Extract(prose); len(got) != 0 {
		t.Errorf("false positives in ordinary prose: %v", got)
	}
}

func TestTypesAreListed(t *testing.T) {
	types := sensitive.Types()
	if len(types) < 15 {
		t.Errorf("only %d types", len(types))
	}
	if !strings.Contains(strings.Join(types, ","), "credit_card_number") {
		t.Error("credit_card_number is not listed")
	}
}
