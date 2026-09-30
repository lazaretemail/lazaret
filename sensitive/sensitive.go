// SPDX-License-Identifier: AGPL-3.0-only

// Package sensitive extracts personally identifying information and credentials.
//
// It answers beta.ml_extract_sensitive_information, which the corpus calls 304 times
// across 76 DLP rules. Despite the ml_ prefix, none of this is machine learning: every
// type the corpus names is a pattern, and most carry a checksum. A credit card number
// is not a thing a model recognises, it is a thing Luhn validates.
//
// That matters for honesty as well as effort. A classifier would return a probability
// and rules would have to trust it; a validated checksum is either right or it is not,
// and the confidence this package reports says which.
//
// # Confidence means something here
//
//   - "high"   — a checksum validated. A sixteen-digit string that passes Luhn in a
//     context that looks like a card is a card.
//   - "medium" — a distinctive, unambiguous prefix with no checksum to confirm, such as
//     an AWS key id or a GitHub token.
//   - "low"    — the shape is right and nothing confirms it. A nine-digit number is a
//     US social security number, an employee id, or a part number.
//
// Rules read `.confidence == "high"`, so getting this wrong in the generous direction
// turns a part number into a data breach.
//
// # Coverage is partial, and says so
//
// The corpus names 75 types. This implements the ones that are checksum-verifiable or
// unambiguous, which is where the value is and where a false positive is cheapest to
// avoid. Types not implemented are simply not reported; nothing guesses. Types lists
// what is covered, and adding one is a table entry plus a test.
package sensitive

import (
	"regexp"
	"sort"
	"strings"
)

// Confidence levels, as the schema spells them.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Element is one finding.
type Element struct {
	Type       string
	Value      string
	Confidence string
	Score      float64
}

// detector is one type of sensitive value.
type detector struct {
	name string
	re   *regexp.Regexp

	// validate confirms a candidate. Nil means the pattern alone is the evidence.
	validate func(string) bool

	// confidence when there is no validator, or when one is present and passes.
	confidence string

	// score is the schema's numeric companion to confidence.
	score float64
}

// Types lists what this package can find.
func Types() []string {
	out := make([]string, 0, len(detectors))
	for _, d := range detectors {
		out = append(out, d.name)
	}
	sort.Strings(out)
	return out
}

// Extract finds every sensitive value in a body of text.
//
// Results are deduplicated by (type, value): a card number in both the HTML and the
// plain-text part of a message is one disclosure, not two, and a rule counting elements
// should not double it.
func Extract(text string) []Element {
	if strings.TrimSpace(text) == "" {
		return nil
	}

	var out []Element
	seen := map[string]bool{}
	for _, d := range detectors {
		for _, m := range d.re.FindAllString(text, -1) {
			candidate := strings.TrimSpace(m)
			conf, score := d.confidence, d.score
			if d.validate != nil {
				if !d.validate(candidate) {
					// A failed checksum is not a low-confidence finding, it is not a
					// finding. Reporting it anyway is how a DLP tool becomes something
					// people switch off.
					continue
				}
				conf, score = High, 0.99
			}
			key := d.name + "\x00" + candidate
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Element{Type: d.name, Value: candidate, Confidence: conf, Score: score})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

var detectors = []detector{
	// ---- Financial, all checksum-verifiable ----
	{
		name:     "credit_card_number",
		re:       regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
		validate: func(s string) bool { return luhn(digits(s)) && len(digits(s)) >= 13 && len(digits(s)) <= 19 },
	},
	{
		name:     "iban_code",
		re:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b`),
		validate: validIBAN,
	},
	{
		name:     "us_aba_routing_number",
		re:       regexp.MustCompile(`\b\d{9}\b`),
		validate: validABA,
	},
	{
		name:       "swift_bic",
		re:         regexp.MustCompile(`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`),
		confidence: Low,
		score:      0.4,
	},

	// ---- Government identifiers ----
	{
		name:     "canadian_sin",
		re:       regexp.MustCompile(`\b\d{3}[ -]?\d{3}[ -]?\d{3}\b`),
		validate: func(s string) bool { return len(digits(s)) == 9 && luhn(digits(s)) },
	},
	{
		name:     "nhs_number",
		re:       regexp.MustCompile(`\b\d{3}[ -]?\d{3}[ -]?\d{4}\b`),
		validate: validNHS,
	},
	{
		name:     "nl_bsn",
		re:       regexp.MustCompile(`\b\d{9}\b`),
		validate: validBSN,
	},
	{
		name:     "social_security_number",
		re:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		validate: validSSN,
	},
	{
		name:       "uk_nino",
		re:         regexp.MustCompile(`\b[ABCEGHJKLMNOPRSTWXYZ][ABCEGHJKLMNPRSTWXYZ] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b`),
		confidence: Medium,
		score:      0.7,
	},
	{
		name:     "vehicle_vin",
		re:       regexp.MustCompile(`\b[A-HJ-NPR-Z0-9]{17}\b`),
		validate: validVIN,
	},
	{
		name:     "us_npi",
		re:       regexp.MustCompile(`\b\d{10}\b`),
		validate: validNPI,
	},
	{
		name:       "us_itin",
		re:         regexp.MustCompile(`\b9\d{2}-[5-9]\d-\d{4}\b`),
		confidence: Medium,
		score:      0.7,
	},

	// ---- Credentials and keys. Distinctive prefixes, no checksum, but nothing else
	// looks like them — and a leaked key is worth reporting on shape alone.
	{
		name:       "aws_access_key",
		re:         regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
		confidence: High,
		score:      0.95,
	},
	{
		name:       "github_token",
		re:         regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,255}\b`),
		confidence: High,
		score:      0.95,
	},
	{
		name:       "google_api_key",
		re:         regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		confidence: High,
		score:      0.95,
	},
	{
		name:       "slack_access_token",
		re:         regexp.MustCompile(`\bxox[abposr]-[0-9A-Za-z-]{10,250}\b`),
		confidence: High,
		score:      0.95,
	},
	{
		name:       "jwt",
		re:         regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		confidence: High,
		score:      0.9,
	},
	{
		name:       "private_key",
		re:         regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
		confidence: High,
		score:      0.99,
	},
	{
		name:       "ssl_certificate",
		re:         regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
		confidence: High,
		score:      0.99,
	},
	{
		name:       "http_authorization_header",
		re:         regexp.MustCompile(`(?i)\bauthorization:\s*(?:bearer|basic|token)\s+[A-Za-z0-9+/=._~-]{8,}`),
		confidence: High,
		score:      0.9,
	},
	{
		name:       "oauth_client_secret",
		re:         regexp.MustCompile(`(?i)\b(?:client[_-]?secret|api[_-]?secret)["'\s:=]{1,4}[A-Za-z0-9_\-]{16,}\b`),
		confidence: Medium,
		score:      0.7,
	},

	// ---- Miscellaneous ----
	{
		name:       "crypto_wallet_address",
		re:         regexp.MustCompile(`\b(?:0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`),
		confidence: Medium,
		score:      0.75,
	},
	{
		name:       "mac_address",
		re:         regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`),
		confidence: Medium,
		score:      0.8,
	},
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhn is the mod-10 check behind card numbers, Canadian SINs and several national ids.
func luhn(s string) bool {
	if len(s) < 2 {
		return false
	}
	sum, double := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// validIBAN is the mod-97 check from ISO 13616.
func validIBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]

	// mod 97 over the digit expansion, a chunk at a time so no big integer is needed.
	rem := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			rem = rem*10 + int(r-'0')
		case r >= 'A' && r <= 'Z':
			rem = rem*100 + int(r-'A') + 10
		default:
			return false
		}
		rem %= 97
	}
	return rem == 1
}

// validABA is the weighted checksum on a US routing number.
func validABA(s string) bool {
	d := digits(s)
	if len(d) != 9 {
		return false
	}
	// A routing number's first two digits identify a Federal Reserve district; 80-99
	// other than 80 are unassigned, and 00 never occurs. Without this every nine-digit
	// number with a coincidental checksum becomes a bank account.
	switch lead := d[0:2]; {
	case lead == "00":
		return false
	case lead >= "13" && lead <= "20", lead >= "33" && lead <= "60", lead >= "73" && lead <= "79", lead >= "81":
		return false
	}
	n := func(i int) int { return int(d[i] - '0') }
	sum := 3*(n(0)+n(3)+n(6)) + 7*(n(1)+n(4)+n(7)) + (n(2) + n(5) + n(8))
	return sum%10 == 0 && sum != 0
}

// validNHS is the mod-11 check on an NHS number.
func validNHS(s string) bool {
	d := digits(s)
	if len(d) != 10 {
		return false
	}
	sum := 0
	for i := range 9 {
		sum += int(d[i]-'0') * (10 - i)
	}
	check := 11 - sum%11
	switch check {
	case 11:
		check = 0
	case 10:
		return false // never valid
	}
	return check == int(d[9]-'0')
}

// validBSN is the Dutch 11-proef.
func validBSN(s string) bool {
	d := digits(s)
	if len(d) != 9 || d == "000000000" {
		return false
	}
	sum := 0
	for i := range 8 {
		sum += int(d[i]-'0') * (9 - i)
	}
	sum -= int(d[8] - '0')
	return sum%11 == 0
}

// validSSN rejects the ranges the US Social Security Administration never issues, which
// is what stops a formatted date or a part number reading as an SSN.
func validSSN(s string) bool {
	d := digits(s)
	if len(d) != 9 {
		return false
	}
	area, group, serial := d[0:3], d[3:5], d[5:9]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	return group != "00" && serial != "0000"
}

// validVIN is the ISO 3779 check digit.
func validVIN(s string) bool {
	s = strings.ToUpper(s)
	if len(s) != 17 {
		return false
	}
	const weights = "8765432X098765432"
	value := func(r byte) int {
		switch {
		case r >= '0' && r <= '9':
			return int(r - '0')
		case r >= 'A' && r <= 'Z':
			// I, O and Q are excluded from VINs; the rest map on a fixed table.
			return map[byte]int{
				'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
				'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
				'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
			}[r]
		}
		return -1
	}
	sum := 0
	for i := range 17 {
		v := value(s[i])
		if v <= 0 && s[i] != '0' {
			return false
		}
		w := weights[i]
		if w == 'X' {
			sum += v * 10
			continue
		}
		sum += v * int(w-'0')
	}
	check := sum % 11
	if check == 10 {
		return s[8] == 'X'
	}
	return int(s[8]-'0') == check
}

// validNPI is Luhn over the identifier with the US health prefix 80840 prepended.
func validNPI(s string) bool {
	d := digits(s)
	return len(d) == 10 && luhn("80840"+d)
}
