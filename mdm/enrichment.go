// SPDX-License-Identifier: AGPL-3.0-only

package mdm

// The types in this file are the enrichment outputs Sublime does not publish a schema for.
//
// Two of the big ones are published, just not where you would look: file.explode's output
// is Strelka's response object and link analysis has its own document, both inlined in the
// markdown of API reference pages. Those are vendored and generated (enrichment.gen.go).
//
// What remains — natural-language classification, WHOIS, sender profiling, OLE analysis,
// OCR, QR, EXIF — has no published shape at all. These structs are reconstructed from how
// the public rule corpus actually uses them, with the observed usage counts recorded
// against each field so the evidence is visible rather than asserted. A field nobody in
// 1,521 rules has ever read is a field we have guessed at, and it is marked as such.
//
// Everything here is behind the enrich interfaces, so nothing populates these yet. They
// exist now because the type checker has to resolve `.intents`, `.brands` and `.days_old`
// to something, and because defining them against the corpus is how modules 3-5 inherit a
// contract rather than inventing one.

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// RegexMatch is one match from regex.extract or regex.iextract.
//
// This one is documented: capture groups are "never null but empty string", which is why
// Groups holds values rather than pointers.
type RegexMatch struct {
	FullMatch   string            `json:"full_match,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	NamedGroups map[string]string `json:"named_groups,omitempty"`
}

// HTML is a parsed HTML document, from strings.parse_html or file.parse_html.
//
// It is deliberately the same shape as the body's HTML part minus the message-specific
// fields: a rule that works on body.html should work on a parsed attachment too.
type HTML struct {
	Raw         *string `json:"raw,omitempty"`
	InnerText   *string `json:"inner_text,omitempty"`
	DisplayText *string `json:"display_text,omitempty"`
	Links       []*Link `json:"links,omitempty"`
}

// HTMLXPathResult is the result of html.xpath. Corpus: `.nodes` (63 uses), read with
// `.inner_text`, `.raw` and `.display_text` on each node.
type HTMLXPathResult struct {
	Nodes []*HTMLNode `json:"nodes,omitempty"`
}

// HTMLNode is one element matched by an XPath query. Corpus also reads `.links` (14),
// since selecting a container and then inspecting its links is a common shape.
type HTMLNode struct {
	Raw         *string `json:"raw,omitempty"`
	InnerText   *string `json:"inner_text,omitempty"`
	DisplayText *string `json:"display_text,omitempty"`
	Links       []*Link `json:"links,omitempty"`
}

// ParseTextOutput is the result of file.parse_text. Corpus: `.text` (67 uses).
type ParseTextOutput struct {
	Text *string `json:"text,omitempty"`
}

// ExpandArchivesResult is the result of file.expand_archives, which extracts nested
// archives without scanning them.
type ExpandArchivesResult struct {
	Files []*File `json:"files,omitempty"`
}

// OleToolsOutput is the result of file.oletools, an OLE2 and Office document analysis.
// Corpus: `.relationships` (8), `.macros.keywords` (2), `.indicators.*` (5).
type OleToolsOutput struct {
	Indicators    *OleIndicators     `json:"indicators,omitempty"`
	Macros        *OleMacros         `json:"macros,omitempty"`
	Relationships []*OleRelationship `json:"relationships,omitempty"`
}

// OleIndicators are oletools' per-document findings.
type OleIndicators struct {
	VBAMacros             *OleIndicator      `json:"vba_macros,omitempty"`
	Encryption            *OleIndicator      `json:"encryption,omitempty"`
	FileFormat            *OleIndicator      `json:"file_format,omitempty"`
	ExternalRelationships *OleIndicatorCount `json:"external_relationships,omitempty"`
}

// OleIndicator is one indicator. Corpus reads `.exists` and `.risk`; `.value` appears on
// file_format.
type OleIndicator struct {
	Exists *bool   `json:"exists,omitempty"`
	Risk   *string `json:"risk,omitempty"`
	Value  *string `json:"value,omitempty"`
}

// OleIndicatorCount is an indicator whose finding is a count.
type OleIndicatorCount struct {
	Count *int64 `json:"count,omitempty"`
}

// OleMacros holds extracted VBA.
type OleMacros struct {
	Keywords          []*OleKeyword `json:"keywords,omitempty"`
	VBACodeAllModules *string       `json:"vba_code_all_modules,omitempty"`
}

// OleKeyword is one suspicious VBA keyword. Corpus reads `.type` (for example "autoexec").
type OleKeyword struct {
	Type        *string `json:"type,omitempty"`
	Keyword     *string `json:"keyword,omitempty"`
	Description *string `json:"description,omitempty"`
}

// OleRelationship is an OOXML relationship, which is how remote template injection works.
// Corpus reads `.target_url` (17) far more than `.target`, because what matters is where
// the document reaches out to.
type OleRelationship struct {
	Target    *string `json:"target,omitempty"`
	TargetURL *URL    `json:"target_url,omitempty"`
	Name      *string `json:"name,omitempty"`
	Type      *string `json:"type,omitempty"`
}

// MLMacrosOutput is the result of ml.macro_classifier. Corpus: `.malicious`, `.confidence`.
type MLMacrosOutput struct {
	Malicious  *bool   `json:"malicious,omitempty"`
	Confidence *string `json:"confidence,omitempty"`
}

// LogoDetectOutput is the result of ml.logo_detect.
//
// Corpus: `any(ml.logo_detect(f).brands, .name == "Coinbase")` — 44 uses of `.brands`, 28
// of `.name` within one.
type LogoDetectOutput struct {
	Brands []*DetectedBrand `json:"brands,omitempty"`
}

// DetectedBrand is one brand the model recognised in an image.
type DetectedBrand struct {
	Name       *string  `json:"name,omitempty"`
	Confidence *string  `json:"confidence,omitempty"`
	Score      *float64 `json:"score,omitempty"`
}

// NluResult is the result of ml.nlu_classifier.
//
// One function covers three capabilities, and the corpus reads all of them:
// `.intents` (290), `.entities` (182), `.topics` (142), `.tags` (19), plus `.language`.
// Each is a list of named, scored findings read as `any(..., .name == "cred_theft")`.
type NluResult struct {
	Intents  []*NluFinding `json:"intents,omitempty"`
	Entities []*NluFinding `json:"entities,omitempty"`
	Topics   []*NluFinding `json:"topics,omitempty"`
	Tags     []*NluFinding `json:"tags,omitempty"`

	// Language is the detected language of the input.
	Language *string `json:"language,omitempty"`

	// Text is the input as the classifier saw it, after any normalisation.
	Text *string `json:"text,omitempty"`
}

// NluFinding is one classification. Intents are values such as bec, cred_theft, extortion;
// entities are the parts of a message the model recognised, such as urgency or financial.
//
// Text is the span that triggered the finding, and the corpus reads it 100 times — an
// entity is only actionable if a rule can see the words behind it.
type NluFinding struct {
	Name       *string  `json:"name,omitempty"`
	Text       *string  `json:"text,omitempty"`
	Confidence *string  `json:"confidence,omitempty"`
	Score      *float64 `json:"score,omitempty"`
}

// SensitiveInfoOutput is the result of beta.ml_extract_sensitive_information, the DLP
// extractor. Corpus: `.elements` (304 uses), read with `.type`.
type SensitiveInfoOutput struct {
	Elements []*SensitiveElement `json:"elements,omitempty"`
}

// SensitiveElement is one piece of sensitive data found in a message, such as a national
// identity number or a payment card.
type SensitiveElement struct {
	Type       *string  `json:"type,omitempty"`
	Value      *string  `json:"value,omitempty"`
	Confidence *string  `json:"confidence,omitempty"`
	Score      *float64 `json:"score,omitempty"`
}

// OCROutput is the result of beta.ocr. Corpus: `.text` (65), `.page_results[0].text` (4),
// `.success` (2).
type OCROutput struct {
	Text        *string    `json:"text,omitempty"`
	Success     *bool      `json:"success,omitempty"`
	PageResults []*OCRPage `json:"page_results,omitempty"`
	Screenshot  *File      `json:"screenshot,omitempty"`
}

// OCRPage is the text recognised on one page of a multi-page document.
type OCRPage struct {
	Text *string `json:"text,omitempty"`
}

// QRScanOutput is the result of beta.scan_qr. Corpus:
// `any(beta.scan_qr(file.message_screenshot()).items, .type == "url")`.
type QRScanOutput struct {
	Found *bool     `json:"found,omitempty"`
	Items []*QRItem `json:"items,omitempty"`
}

// QRItem is one decoded QR code. A QR code carrying a URL is the point of the whole
// technique: it moves the link out of anything that scans text.
type QRItem struct {
	Type *string `json:"type,omitempty"`
	Data *string `json:"data,omitempty"`
	URL  *URL    `json:"url,omitempty"`
}

// ExifOutput is the result of beta.parse_exif. Corpus: `.fields` (25), plus the named
// convenience fields `.creator` (20), `.producer` (13), `.page_count` (13), `.title` (8),
// `.image_height` (6), `.image_width` (4), `.author` (3).
type ExifOutput struct {
	Fields []*ExifField `json:"fields,omitempty"`

	Creator     *string `json:"creator,omitempty"`
	Producer    *string `json:"producer,omitempty"`
	Title       *string `json:"title,omitempty"`
	Author      *string `json:"author,omitempty"`
	PageCount   *int64  `json:"page_count,omitempty"`
	ImageHeight *int64  `json:"image_height,omitempty"`
	ImageWidth  *int64  `json:"image_width,omitempty"`
}

// ExifField is one raw metadata entry. Corpus reads `.key` and `.value`.
type ExifField struct {
	Key   *string `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
}

// WhoisOutput is the result of network.whois.
//
// Corpus: `.days_old` (116 uses) dominates — a domain registered last week is the single
// most reliable cheap signal there is. Then `.found` (9), `.registrar_name` (7),
// `.name_servers` (5), `.registrant_company` (4), `.registrant_country_code` (3).
type WhoisOutput struct {
	Found   *bool   `json:"found,omitempty"`
	Domain  *Domain `json:"domain,omitempty"`
	DaysOld *int64  `json:"days_old,omitempty"`

	RegistrarName         *string `json:"registrar_name,omitempty"`
	RegistrantCompany     *string `json:"registrant_company,omitempty"`
	RegistrantEmail       *string `json:"registrant_email,omitempty"`
	RegistrantName        *string `json:"registrant_name,omitempty"`
	RegistrantCountryCode *string `json:"registrant_country_code,omitempty"`
	RegistrantCountry     *string `json:"registrant_country,omitempty"`
	TechnicalEmail        *string `json:"technical_email,omitempty"`
	AdministrativeEmail   *string `json:"administrative_email,omitempty"`

	// NameServers are domains rather than plain strings: rules read `.root_domain` off
	// them to spot a whole hosting provider at once, which is more durable than matching
	// individual nameserver hostnames.
	NameServers []*Domain `json:"name_servers,omitempty"`
}

// SenderProfile is the result of the profile.* functions.
//
// Corpus: `.any_messages_benign` (233), `.solicited` (186),
// `.any_messages_malicious_or_spam` (170), `.prevalence` (72), `.any_false_positives` (6),
// plus `.days_known` and `.days_since.*`.
//
// The documented caveat matters more than the shape: results are relative to the time of
// the message being evaluated, so a backtest sees only what was known then. Prevalence
// stays "new" for eight to twelve hours by design, which means a profile is a statement
// about a moment rather than a fact about a sender.
type SenderProfile struct {
	// Prevalence is how often this sender has been seen: "new", "outlier", "common", or
	// "unknown" when there is not enough history to say.
	Prevalence *string `json:"prevalence,omitempty"`

	// Solicited reports whether anyone in the organisation has written to them first.
	Solicited *bool `json:"solicited,omitempty"`

	AnyMessagesMaliciousOrSpam *bool `json:"any_messages_malicious_or_spam,omitempty"`
	AnyMessagesBenign          *bool `json:"any_messages_benign,omitempty"`
	AnyFalsePositives          *bool `json:"any_false_positives,omitempty"`
	AuthFailed                 *bool `json:"auth_failed,omitempty"`

	DaysKnown *int64           `json:"days_known,omitempty"`
	DaysSince *SenderDaysSince `json:"days_since,omitempty"`
}

// SenderDaysSince records how long ago the last contact was, in each direction.
type SenderDaysSince struct {
	FirstContact *int64 `json:"first_contact,omitempty"`
	LastContact  *int64 `json:"last_contact,omitempty"`
	LastInbound  *int64 `json:"last_inbound,omitempty"`
	LastOutbound *int64 `json:"last_outbound,omitempty"`
}

// AttackScore is the result of ml.attack_score and beta.fuzzy_attack_score.
type AttackScore struct {
	Score      *float64 `json:"score,omitempty"`
	Confidence *string  `json:"confidence,omitempty"`
	Verdict    *string  `json:"verdict,omitempty"`
}

// ICSOutput is the result of beta.file.parse_ics.
//
// Distinct from the ICS scanner inside file.explode: this one exposes events directly,
// which is what calendar-invite phishing rules iterate over.
type ICSOutput struct {
	Events []*ICSEvent `json:"events,omitempty"`

	// ProductID identifies the software that produced the invitation, and Scale is its
	// calendar system. A non-Gregorian scale in business mail is not a localisation
	// choice, it is a parser-confusion attempt.
	ProductID *string `json:"product_id,omitempty"`
	Scale     *string `json:"scale,omitempty"`
	Method    *string `json:"method,omitempty"`
	Version   *string `json:"version,omitempty"`

	RawProperties []*ICSProperty `json:"raw_properties,omitempty"`
}

// ICSEvent is one calendar event. Invitations are a delivery channel in their own right —
// the link lives in the description and the victim is added to their own calendar.
type ICSEvent struct {
	Name    *string `json:"name,omitempty"`
	Summary *string `json:"summary,omitempty"`
	UID     *string `json:"uid,omitempty"`

	Description *string `json:"description,omitempty"`

	// DescriptionHTML is the rich-text alternative some clients attach. Worth keeping
	// separate: the link in an invitation often exists only in the HTML form.
	DescriptionHTML *string `json:"description_html,omitempty"`

	Location  *string    `json:"location,omitempty"`
	Organizer *Mailbox   `json:"organizer,omitempty"`
	Attendees []*Mailbox `json:"attendees,omitempty"`
	Links     []*Link    `json:"links,omitempty"`

	// RawProperties are the calendar properties as written, including the X- extensions
	// that carry no standard meaning. Rules count them: an invitation stuffed with
	// hex-valued custom properties is not an invitation anyone means to send.
	RawProperties []*ICSProperty `json:"raw_properties,omitempty"`
}

// ICSProperty is one raw calendar property, name and value as they appeared.
type ICSProperty struct {
	Name  *string `json:"name,omitempty"`
	Value *string `json:"value,omitempty"`
}

// TranslateOutput is the result of beta.ml_translate.
type TranslateOutput struct {
	Text           *string `json:"text,omitempty"`
	SourceLanguage *string `json:"source_language,omitempty"`
}

// ---------------------------------------------------------------------------
// Lazaret extensions
//
// The types below are not part of Sublime's Message Data Model. MQL has no IP or ASN
// function, so nothing in the public rule corpus can reach them; they exist for the
// extension functions this engine registers under the `rdap` namespace, and they are kept
// here rather than in the generated files because upstream has nothing to say about them.
// ---------------------------------------------------------------------------

// IPInfo is registration data for an IP address, from the RIR that holds it.
//
// The useful question about an address in a Received chain is rarely which address it is
// but whose network it belongs to. Attackers rotate addresses freely and netblocks
// slowly, so the allocation outlives any individual host.
type IPInfo struct {
	// Found is false when the address is in unallocated, reserved or private space.
	Found *bool `json:"found,omitempty"`

	IP *string `json:"ip,omitempty"`

	// Organization is the entity holding the range — the single most useful field here.
	Organization *string `json:"organization,omitempty"`

	// Name is the registry's short label for the range, such as "GOGL".
	Name *string `json:"name,omitempty"`

	// Handle identifies the range within its registry. Its format differs between RIRs:
	// ARIN writes "NET-8-8-8-0-2", RIPE writes "193.0.0.0 - 193.0.7.255".
	Handle *string `json:"handle,omitempty"`

	// Type is the allocation type, such as "DIRECT ALLOCATION" or "ASSIGNED PA".
	Type *string `json:"type,omitempty"`

	// CIDR holds the range in prefix form, from the cidr0 extension. There may be more
	// than one.
	CIDR []string `json:"cidr,omitempty"`

	StartAddress *string `json:"start_address,omitempty"`
	EndAddress   *string `json:"end_address,omitempty"`
	ParentHandle *string `json:"parent_handle,omitempty"`

	Country *string `json:"country,omitempty"`

	// DaysOld is how long ago the range was allocated. A netblock allocated last month
	// that is already sending mail is worth a second look.
	DaysOld *int64 `json:"days_old,omitempty"`

	// ASNs are the autonomous systems announcing this range, where the registry
	// publishes them. ARIN does; not every RIR does, so this is often empty.
	ASNs []int64 `json:"asns,omitempty"`

	AbuseEmail *string  `json:"abuse_email,omitempty"`
	Status     []string `json:"status,omitempty"`
}

// ASNInfo is registration data for an autonomous system number.
type ASNInfo struct {
	Found *bool  `json:"found,omitempty"`
	ASN   *int64 `json:"asn,omitempty"`

	// Organization is the entity operating the AS.
	Organization *string `json:"organization,omitempty"`

	Name   *string `json:"name,omitempty"`
	Handle *string `json:"handle,omitempty"`
	Type   *string `json:"type,omitempty"`

	// StartASN and EndASN bound the block this number was allocated within.
	StartASN *int64 `json:"start_asn,omitempty"`
	EndASN   *int64 `json:"end_asn,omitempty"`

	Country *string `json:"country,omitempty"`
	DaysOld *int64  `json:"days_old,omitempty"`

	AbuseEmail *string  `json:"abuse_email,omitempty"`
	Status     []string `json:"status,omitempty"`
}

// ---------------------------------------------------------------------------
// Strelka wire-format compatibility
// ---------------------------------------------------------------------------

// UnmarshalJSON reads both shapes of a YARA scan result.
//
// StrelkaYARA is generated from Sublime's published schema, which models a match as an
// object — `matches: [{name, meta}]`. Strelka does not emit that. Its ScanYara appends
// `match.rule`, a bare string, and puts metadata in a separate parallel list keyed by
// rule name:
//
//	{"matches": ["lazaret_script_obfuscation"],
//	 "meta": [{"rule": "lazaret_script_obfuscation",
//	           "identifier": "author", "value": "Lazaret"}],
//	 "tags": [...], "rules_loaded": 2}
//
// So the published schema is once again a joined view of two wire fields, exactly as it
// is for the file metadata that convert.go lifts. The join is done here, on the type, so
// that anything decoding a Strelka response — the client, a stored fixture, a future
// service — gets the same result, and so that rules can read `.name` and `.meta` the way
// the schema says they can.
//
// Both forms are accepted because the published one is what Sublime's own API returns,
// and the corpus is written against that.
//
// This was found by a live scan: a signature matched for the first time, and the record
// stopped decoding. Until something matched, `matches` was always empty and the two
// shapes were indistinguishable. It is the same lesson as convert.go — a fixture written
// from the published schema agrees with itself and proves nothing.
func (y *StrelkaYARA) UnmarshalJSON(b []byte) error {
	// An alias, so unmarshalling the envelope does not re-enter this method.
	type wire struct {
		Flags   []string          `json:"flags"`
		Matches []json.RawMessage `json:"matches"`
		Meta    []struct {
			Rule       string `json:"rule"`
			Identifier string `json:"identifier"`
			Value      any    `json:"value"`
		} `json:"meta"`
	}

	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}

	y.Flags = w.Flags
	y.Matches = nil

	byName := make(map[string]*StrelkaYARAMatch, len(w.Matches))
	for _, raw := range w.Matches {
		m := &StrelkaYARAMatch{}
		// Strelka's form: a bare rule name.
		var name string
		if err := json.Unmarshal(raw, &name); err == nil {
			m.Name = Ptr(name)
		} else if err := json.Unmarshal(raw, m); err != nil {
			// Neither shape. Reporting it beats dropping a match silently — an
			// undetected match is a missed detection.
			return fmt.Errorf("mdm: yara match is neither a rule name nor a match object: %w", err)
		}
		y.Matches = append(y.Matches, m)
		if m.Name != nil {
			byName[*m.Name] = m
		}
	}

	// Fold the parallel meta list onto the match it belongs to. Strelka only emits it
	// when the scanner is configured with show_all_meta or meta_fields, so its absence
	// is normal and not a signal that anything is wrong.
	for _, e := range w.Meta {
		m, ok := byName[e.Rule]
		if !ok {
			// Meta for a rule that is not in matches: keep it rather than discard it,
			// since it still names a rule that fired.
			m = &StrelkaYARAMatch{Name: Ptr(e.Rule)}
			byName[e.Rule] = m
			y.Matches = append(y.Matches, m)
		}
		if m.Meta == nil {
			m.Meta = make(map[string]string)
		}
		// The schema types meta values as strings; YARA allows integers and booleans
		// too, so anything else is rendered rather than dropped.
		switch v := e.Value.(type) {
		case string:
			m.Meta[e.Identifier] = v
		case nil:
			m.Meta[e.Identifier] = ""
		default:
			m.Meta[e.Identifier] = fmt.Sprint(v)
		}
	}

	return nil
}

// The three decoders below exist for the same reason StrelkaYARA.UnmarshalJSON does: the
// published schema describes what Sublime's API returns, and Strelka's wire format is not
// that. See docs/ARCHITECTURE.md, "The published schema is not the wire format".
//
// All three shapes were captured from a real scan of a real file, never transcribed from
// the schema, and each has a live test that exercises a non-empty result.

// exifTagNames restores exiftool's canonical tag names.
//
// Strelka lowercases every key, so `Creator` arrives as `creator`. That matters because
// the corpus compares tag names literally — `.key == "Software"` (10 uses), `"Model"`
// (10), `"DeviceManufacturer"` (9), and so on — and a lowercase key silently matches
// none of them. The casing is not mechanically recoverable (`titlesofparts` ->
// `TitlesOfParts`), so the tags the corpus actually names are tabulated and anything
// unlisted keeps the key Strelka sent.
//
// Add to this table when a rule needs a tag it does not cover.
var exifTagNames = map[string]string{
	"artist":             "Artist",
	"author":             "Author",
	"characters":         "Characters",
	"company":            "Company",
	"createdate":         "CreateDate",
	"creator":            "Creator",
	"creatortool":        "CreatorTool",
	"devicemanufacturer": "DeviceManufacturer",
	"encryption":         "Encryption",
	"filetype":           "FileType",
	"hyperlinks":         "Hyperlinks",
	"imagedescription":   "ImageDescription",
	"imageheight":        "ImageHeight",
	"imagewidth":         "ImageWidth",
	"keywords":           "Keywords",
	"lastmodifiedby":     "LastModifiedBy",
	"model":              "Model",
	"modifydate":         "ModifyDate",
	"pagecount":          "PageCount",
	"producer":           "Producer",
	"software":           "Software",
	"subject":            "Subject",
	"title":              "Title",
	"titlesofparts":      "TitlesOfParts",
	"usercomment":        "UserComment",
	"warning":            "Warning",
}

// exifScannerKeys are exiftool outputs that describe the scan rather than the document.
//
// Strelka scans a copy in a temporary directory, so these carry its internal paths —
// `sourcefile: /tmp/tmpuw7vkgpn` — which are not metadata, tell a rule author nothing,
// and needlessly report the scanning host's layout to anyone who can see a match.
var exifScannerKeys = map[string]bool{
	"directory": true, "elapsed": true, "exiftoolversion": true,
	"fileaccessdate": true, "fileinodechangedate": true, "filemodifydate": true,
	"filename": true, "filepermissions": true, "sourcefile": true,
}

// UnmarshalJSON accepts exiftool's wire shape: one flat object of lowercased tag names.
//
// The published schema instead presents a `fields` array of {key, value} plus a handful
// of named conveniences, so this fills both from the same flat map.
func (e *StrelkaExifTool) UnmarshalJSON(b []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("mdm: decoding scan.exiftool: %w", err)
	}

	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys) // rule output should not depend on Go's map ordering

	for _, k := range keys {
		if exifScannerKeys[k] {
			continue
		}
		name := k
		if canonical, ok := exifTagNames[k]; ok {
			name = canonical
		}
		value := renderExifValue(raw[k])
		e.Fields = append(e.Fields, &StrelkaKeyVal{Key: Ptr(name), Value: Ptr(value)})

		switch k {
		case "creator":
			e.Creator = Ptr(value)
		case "producer":
			e.Producer = Ptr(value)
		case "title":
			e.Title = Ptr(value)
		case "filetype":
			e.FileType = Ptr(value)
		case "filetypeextension":
			e.FileTypeExtension = Ptr(value)
		case "linearized":
			e.Linearized = Ptr(value)
		case "pagecount":
			e.PageCount = exifInt(raw[k])
		case "imageheight":
			e.ImageHeight = exifInt(raw[k])
		case "imagewidth":
			e.ImageWidth = exifInt(raw[k])
		}
	}
	return nil
}

// renderExifValue flattens one exiftool value to the string the schema declares. Numbers
// keep their integer form where they have one, so `pagecount: 3` does not become "3.0"
// and defeat a string comparison in a rule.
func renderExifValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}

func exifInt(v any) *int64 {
	switch t := v.(type) {
	case float64:
		n := int64(t)
		return &n
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			return &n
		}
	}
	return nil
}

// UnmarshalJSON accepts Strelka's OCR shape, where `text` is an array of words.
//
// The published schema carries both `raw` ("Full text returned from OCR, including
// whitespace") and `text` ("Array of words found by OCR"), but this Strelka build emits
// only the array — neither `extract_text` nor `split_words` changes that. Since
// `.scan.ocr.raw` is read by 505 corpus rules, more than any other enrichment field, it
// is reconstructed by joining the words with single spaces.
//
// That reconstruction is lossy in exactly one way: the original line breaks and runs of
// whitespace are gone. A rule doing `strings.icontains(.scan.ocr.raw, "verify your
// account")` is unaffected; one written against newline layout would not match. Recorded
// in docs/SEMANTICS.md. If a future Strelka sends `raw`, it is used as-is.
func (o *StrelkaOCR) UnmarshalJSON(b []byte) error {
	var w struct {
		Raw  *string         `json:"raw"`
		Text json.RawMessage `json:"text"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return fmt.Errorf("mdm: decoding scan.ocr: %w", err)
	}

	if len(w.Text) > 0 {
		var words []string
		if err := json.Unmarshal(w.Text, &words); err != nil {
			// Some builds send one string rather than an array of words.
			var single string
			if err2 := json.Unmarshal(w.Text, &single); err2 != nil {
				return fmt.Errorf("mdm: scan.ocr.text is neither a string nor an array: %w", err)
			}
			words = strings.Fields(single)
			if w.Raw == nil {
				w.Raw = &single
			}
		}
		o.Text = words
	}

	switch {
	case w.Raw != nil:
		o.Raw = w.Raw
	case len(o.Text) > 0:
		o.Raw = Ptr(strings.Join(o.Text, " "))
	}
	return nil
}

// UnmarshalJSON accepts Strelka's QR shape, where `data` is an array of decoded payloads.
//
// The published schema declares one `data` string with a `type` and a parsed `url`
// alongside it. Decoding the array into that string is not a lossy translation but a hard
// failure — "cannot unmarshal array into Go struct field StrelkaQR.scan.qr.data" — which
// made every scan of a QR-bearing attachment fail outright, taking the whole of
// file.explode with it. QR codes are current phishing practice, so that is a file this
// engine meets rather than an edge case.
//
// The first payload fills the published shape. `type` and `url` are absent from the wire
// and derived here, because the corpus reads `.scan.qr.type` (32 uses) and
// `.scan.qr.url.*` (86) far more than `.data` itself.
func (q *StrelkaQR) UnmarshalJSON(b []byte) error {
	var w struct {
		Data json.RawMessage `json:"data"`
		Type *string         `json:"type"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return fmt.Errorf("mdm: decoding scan.qr: %w", err)
	}

	payloads, err := stringOrArray(w.Data)
	if err != nil {
		return fmt.Errorf("mdm: scan.qr.data is neither a string nor an array: %w", err)
	}
	if len(payloads) == 0 {
		return nil
	}

	first := payloads[0]
	q.Data = Ptr(first)
	if w.Type != nil {
		t := StrelkaQRType(*w.Type)
		q.Type = &t
	} else {
		t := classifyQRPayload(first)
		q.Type = &t
	}
	if *q.Type == StrelkaQRTypeURL {
		q.URL = ParseURL(first, true)
	}
	return nil
}

// classifyQRPayload maps a decoded payload onto the schema's type enum. A QR code
// carrying a URL is the point of the technique — it moves the link out of anything that
// scans text — so that is the case worth getting right.
func classifyQRPayload(s string) StrelkaQRType {
	lower := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return StrelkaQRTypeURL
	case strings.HasPrefix(lower, "mailto:"):
		return StrelkaQRTypeEmail
	case strings.HasPrefix(lower, "tel:"), strings.HasPrefix(lower, "sms:"):
		return StrelkaQRTypeMobile
	case strings.HasPrefix(lower, "geo:"):
		return StrelkaQRTypeGeo
	case strings.HasPrefix(lower, "wifi:"):
		return StrelkaQRTypeWifi
	case strings.HasPrefix(lower, "market://"), strings.HasPrefix(lower, "itms-apps://"):
		return StrelkaQRTypeApp
	default:
		return StrelkaQRTypeUndefined
	}
}

// stringOrArray accepts either encoding of a field Strelka may send both ways.
func stringOrArray(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []string{one}, nil
}
