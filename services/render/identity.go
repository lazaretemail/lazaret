// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"sort"
	"strings"
)

// What this service says it is when it visits a link.
//
// A credential-harvesting page that serves a benign document to anything identifying
// itself as a scanner is standard practice — cloaking is in every phishing kit worth the
// name, and blocking non-browser clients is how a kit evades analysis. So this is not
// politeness, it is whether the answer we get is the one the recipient got.
//
// # Why this is a profile and not a set of strings
//
// The platform is not one value. It appears in the user agent's parenthesised token, in
// Sec-CH-UA-Platform, and in the Client Hints metadata as a platform, a version and an
// architecture. Letting an operator set them independently means letting them ship a
// browser that claims Windows in one header and X11/Linux in another — and a cloaking
// check does not need to detect a headless browser, only an inconsistent one. That
// mismatch is the exact bug this identity work started from, so the configuration
// surface is a platform *name*, and everything that has to agree is derived from it.
//
// The language list is free text, because it is genuinely a preference: a deployment
// protecting Spanish-speaking recipients should ask for Spanish, and will be served the
// page that recipient would have seen.
type browserIdentity struct {
	// UserAgent is the full User-Agent header, and what the browser is launched with.
	UserAgent string

	// SecCHUA is the brand list. Independent of platform: it describes the browser,
	// not the machine.
	SecCHUA string

	// Platform is the Sec-CH-UA-Platform value, quoted as that header requires.
	Platform string

	// PlatformName, PlatformVersion and Arch fill the Client Hints metadata, which
	// is a separate CDP call from the user agent and does not follow it.
	PlatformName    string
	PlatformVersion string
	Arch            string

	// AcceptLanguage is the bare list, as Chromium wants it: "en-US,en".
	//
	// Kept without quality values because Chromium appends its own, and supplying
	// them produced "en-US,en;q=0.9;q=0.9" — a malformed header, which is a louder
	// signal than the one it was meant to quieten. The HTTP client, which sets the
	// header itself and gets no such help, uses AcceptLanguageHeader below.
	AcceptLanguage string
}

// The Chrome version everything claims.
//
// Pinned rather than read from whatever Chromium the base image ships. A string that
// drifts with the image makes a visit reproducible only until the next rebuild, and a
// version a few releases behind is a far weaker signal than a self-declared robot:
// plenty of real people have not restarted their browser this month.
const (
	chromeMajor       = "153"
	chromeFullVersion = "153.0.0.0"
)

// Platform names an operator may choose.
const (
	PlatformLinux   = "linux"
	PlatformWindows = "windows"
	PlatformMacOS   = "macos"
)

// platformProfile is everything that has to agree about one platform.
type platformProfile struct {
	uaToken    string // the parenthesised part of the user agent
	chPlatform string
	version    string
	arch       string
}

var platformProfiles = map[string]platformProfile{
	PlatformLinux: {
		uaToken: "X11; Linux x86_64", chPlatform: "Linux", version: "6.8.0", arch: "x86",
	},
	PlatformWindows: {
		// Windows 11 still reports NT 10.0 in the user agent and distinguishes
		// itself only through the Client Hints version, which is why both are here.
		uaToken: "Windows NT 10.0; Win64; x64", chPlatform: "Windows", version: "15.0.0", arch: "x86",
	},
	PlatformMacOS: {
		// Frozen at 10_15_7 in the user agent, as Chrome does on every later macOS.
		uaToken: "Macintosh; Intel Mac OS X 10_15_7", chPlatform: "macOS", version: "14.5.0", arch: "x86",
	},
}

// newIdentity builds a coherent identity, or refuses.
//
// Refuses at start-up rather than falling back, for the same reason the link browser
// endpoint does: a deployment that quietly ignored the platform it was configured with
// would be presenting one thing while its operator believed it presented another, and
// the only symptom would be pages behaving oddly months later.
func newIdentity(platform, acceptLanguage string) (browserIdentity, error) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" {
		platform = PlatformLinux
	}
	p, ok := platformProfiles[platform]
	if !ok {
		return browserIdentity{}, fmt.Errorf(
			"%q is not a platform this can present as; choose one of %s",
			platform, strings.Join(knownPlatforms(), ", "))
	}

	langs, err := normaliseLanguages(acceptLanguage)
	if err != nil {
		return browserIdentity{}, err
	}

	return browserIdentity{
		UserAgent: "Mozilla/5.0 (" + p.uaToken + ") AppleWebKit/537.36 (KHTML, like Gecko) " +
			"Chrome/" + chromeFullVersion + " Safari/537.36",
		// The "Not A Brand" entry is not a joke: Chrome includes a deliberately
		// meaningless brand so that servers cannot parse the list naively, and a
		// list without one is itself unusual.
		SecCHUA: `"Not_A Brand";v="8", "Chromium";v="` + chromeMajor +
			`", "Google Chrome";v="` + chromeMajor + `"`,
		Platform:        `"` + p.chPlatform + `"`,
		PlatformName:    p.chPlatform,
		PlatformVersion: p.version,
		Arch:            p.arch,
		AcceptLanguage:  langs,
	}, nil
}

func knownPlatforms() []string {
	out := make([]string, 0, len(platformProfiles))
	for k := range platformProfiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AcceptLanguageHeader is the header form, with the quality values a browser sends.
//
// Chrome weights the list descending from the second entry — "es-ES,es;q=0.9,en;q=0.8" —
// and a list of bare tags with no weights at all is not what any browser sends.
func (b browserIdentity) AcceptLanguageHeader() string {
	tags := strings.Split(b.AcceptLanguage, ",")
	var sb strings.Builder
	q := 9
	for i, tag := range tags {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(tag)
		if i > 0 {
			fmt.Fprintf(&sb, ";q=0.%d", q)
			if q > 1 {
				q--
			}
		}
	}
	return sb.String()
}

// normaliseLanguages checks a language list and strips any quality values.
//
// Strips them because the two consumers want different things: Chromium appends its own
// and doubles anything supplied, while the HTTP client needs them present. Holding the
// bare list and deriving both is the only way those cannot disagree.
func normaliseLanguages(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "en-US,en", nil
	}

	var out []string
	for _, part := range strings.Split(raw, ",") {
		tag := strings.TrimSpace(part)
		if i := strings.Index(tag, ";"); i >= 0 {
			tag = strings.TrimSpace(tag[:i])
		}
		if tag == "" {
			continue
		}
		if !validLanguageTag(tag) {
			return "", fmt.Errorf("%q is not a language tag; expected something like "+
				"es-ES, es, or pt-BR", tag)
		}
		out = append(out, tag)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("no language tags in %q", raw)
	}
	return strings.Join(out, ","), nil
}

// validLanguageTag accepts the shapes that appear in a real Accept-Language.
//
// Deliberately narrow. This string is put into a header verbatim, so anything that is
// not letters, digits and hyphens has no business in it — a header this service sends on
// behalf of an operator should not be a way to send arbitrary bytes to a remote host.
func validLanguageTag(tag string) bool {
	if len(tag) < 2 || len(tag) > 35 {
		return false
	}
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	// A tag neither starts nor ends with the separator.
	return !strings.HasPrefix(tag, "-") && !strings.HasSuffix(tag, "-")
}
