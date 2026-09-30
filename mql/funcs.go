// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
)

// This file is the function surface of the language: what exists, what it takes, what it
// returns, and — for anything the engine cannot compute from the message alone — which
// capability it needs.
//
// The signatures come from Sublime's documentation where there is any, and from how the
// public corpus actually calls each function where there is not. Where the two disagree,
// the corpus wins: a signature that rejects a rule people are running today is wrong
// whatever the docs say.

// Param is one function parameter.
type Param struct {
	Name string

	// Type the argument must be assignable to. Nil means anything.
	Type *mdm.Type

	// Default, for keyword parameters. Documentation only; the evaluator holds the real
	// defaults.
	Default string
}

// Scope describes how a function introduces a new loop scope for its later arguments.
type Scope uint8

const (
	// ScopeNone: every argument is evaluated in the enclosing scope.
	ScopeNone Scope = iota

	// ScopeElement: arguments after the first are evaluated with `.` bound to an element
	// of the first argument's array. This is how any, all, filter and map work, and it is
	// the only place the language grows a new scope.
	ScopeElement
)

// Func is one entry in the function registry.
type Func struct {
	Name     string
	Params   []Param
	Variadic *Param
	Keywords []Param

	// Return is the result type. Nil when Returns is set.
	Return *mdm.Type

	// Returns computes a result type that depends on the arguments, as for filter, which
	// returns an array of whatever it was given.
	Returns func(args []*mdm.Type) *mdm.Type

	Scope Scope

	// Capability is the enrichment this function needs, or empty when it is computable
	// from the message alone. A rule calling a function with a capability the deployment
	// cannot provide evaluates to indeterminate rather than to false.
	Capability enrich.Capability

	// Doc is a one-line description, surfaced in diagnostics and editor tooling.
	Doc string
}

// Pure reports whether the function can be computed from the message alone.
func (f *Func) Pure() bool { return f.Capability == "" }

// Arity returns the minimum and maximum argument counts; max is -1 when variadic.
func (f *Func) Arity() (min, max int) {
	min = len(f.Params)
	if f.Variadic != nil {
		return min, -1
	}
	return min, min
}

// Registry holds the functions a rule may call.
//
// It is a value rather than a package global so that a deployment can add its own
// namespaces without the additions leaking into compatibility testing. Strict mode refuses
// anything outside Sublime's documented surface, which is what keeps a local extension
// from silently becoming a rule that only runs here.
type Registry struct {
	funcs  map[string]*Func
	strict bool
}

// NewRegistry returns the standard function set.
func NewRegistry() *Registry {
	r := &Registry{funcs: make(map[string]*Func, len(standardFuncs))}
	for _, f := range standardFuncs {
		r.funcs[f.Name] = f
	}
	return r
}

// Strict marks the registry as closed to non-Sublime functions. Registering into a strict
// registry fails, which is what makes "does the corpus still pass?" a meaningful question
// after someone has added their own namespace.
func (r *Registry) Strict() *Registry { r.strict = true; return r }

// Register adds a function. The name must be namespaced (`acme.reputation`) so that local
// additions can never collide with a future upstream builtin.
func (r *Registry) Register(f *Func) error {
	if r.strict {
		return fmt.Errorf("registry is strict: cannot add %q", f.Name)
	}
	if _, exists := r.funcs[f.Name]; exists {
		return fmt.Errorf("function %q is already registered", f.Name)
	}
	if !strings.Contains(f.Name, ".") {
		return fmt.Errorf("extension function %q must be namespaced, as in acme.%s", f.Name, f.Name)
	}
	r.funcs[f.Name] = f
	return nil
}

// Lookup finds a function by its fully qualified name.
func (r *Registry) Lookup(name string) (*Func, bool) {
	f, ok := r.funcs[name]
	return f, ok
}

// Names lists every registered function, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.funcs))
	for n := range r.funcs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Capabilities returns the distinct capabilities the registry's functions need.
func (r *Registry) Capabilities() []enrich.Capability {
	seen := map[enrich.Capability]bool{}
	var out []enrich.Capability
	for _, f := range r.funcs {
		if f.Capability != "" && !seen[f.Capability] {
			seen[f.Capability] = true
			out = append(out, f.Capability)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---------------------------------------------------------------------------
// The standard function set
// ---------------------------------------------------------------------------

// Shorthands, so the table below reads as a specification rather than as Go.
var (
	tBool   = mdm.Bool
	tInt    = mdm.Int
	tFloat  = mdm.Float
	tStr    = mdm.String
	tAny    = mdm.Any
	tStrArr = mdm.StringArray
	tAnyArr = mdm.AnyArray
)

func p(name string, t *mdm.Type) Param { return Param{Name: name, Type: t} }

func kw(name string, t *mdm.Type, def string) Param {
	return Param{Name: name, Type: t, Default: def}
}

// elemOf returns the element type of the first argument, defaulting to Any. Used by the
// array functions, whose result type follows their input.
func elemOf(args []*mdm.Type) *mdm.Type {
	if len(args) == 0 {
		return tAny
	}
	if e := args[0].Elem_(); e != nil {
		return e
	}
	return tAny
}

func sameAsFirst(args []*mdm.Type) *mdm.Type {
	if len(args) == 0 {
		return tAny
	}
	return args[0]
}

var standardFuncs = concat(
	builtinFuncs,
	stringFuncs,
	regexFuncs,
	htmlFuncs,
	hashFuncs,
	aliasFuncs,
	fileFuncs,
	mlFuncs,
	networkFuncs,
	profileFuncs,
	betaFuncs,
)

func concat(sets ...[]*Func) []*Func {
	var out []*Func
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// builtinFuncs are the unnamespaced functions: array and map operations, plus length and
// coalesce. Between them they account for the largest share of calls in the corpus —
// `any` alone appears 4,427 times.
var builtinFuncs = []*Func{
	{
		Name: "any", Params: []Param{p("array", tAnyArr), p("expression", tBool)},
		Return: tBool, Scope: ScopeElement,
		Doc: "true when the expression holds for at least one element",
	},
	{
		Name: "all", Params: []Param{p("array", tAnyArr), p("expression", tBool)},
		Return: tBool, Scope: ScopeElement,
		Doc: "true when the expression holds for every element; vacuously true when empty",
	},
	{
		Name: "filter", Params: []Param{p("array", tAnyArr), p("expression", tBool)},
		Returns: sameAsFirst, Scope: ScopeElement,
		Doc: "the elements for which the expression holds",
	},
	{
		Name: "map", Params: []Param{p("array", tAnyArr), p("expression", nil)},
		Returns: func(args []*mdm.Type) *mdm.Type {
			if len(args) < 2 {
				return tAnyArr
			}
			return mdm.ArrayOf(args[1])
		},
		Scope: ScopeElement,
		Doc:   "the expression evaluated for each element",
	},
	{
		Name: "distinct", Params: []Param{p("array", tAnyArr)},
		Variadic: &Param{Name: "key"}, Returns: sameAsFirst, Scope: ScopeElement,
		Doc: "the array with duplicates removed, optionally by a key expression",
	},
	{
		Name: "flatten", Params: []Param{p("array", tAnyArr)},
		Returns: func(args []*mdm.Type) *mdm.Type {
			// Flattening removes one or more levels of nesting; the leaf type is what
			// comes back. Walking down to it keeps map(flatten(...)) checking properly.
			t := elemOf(args)
			for t != nil && t.Kind == mdm.KindArray {
				t = t.Elem_()
			}
			return mdm.ArrayOf(t)
		},
		Doc: "nested arrays collapsed to a flat array of their leaves",
	},
	{
		Name: "sum", Params: []Param{p("array", tAnyArr)},
		Variadic: &Param{Name: "expression", Type: tFloat}, Return: tFloat, Scope: ScopeElement,
		Doc: "the total of the array, or of an expression over it",
	},
	{
		Name: "ratio", Params: []Param{p("array", tAnyArr), p("expression", tBool)},
		Return: tFloat, Scope: ScopeElement,
		Doc: "the proportion of elements for which the expression holds; null when empty",
	},
	{
		Name: "length", Params: []Param{p("value", nil)}, Return: tInt,
		Doc: "the length of a string in code points, or of an array or map",
	},
	{
		Name: "coalesce", Params: []Param{p("value", nil)},
		Variadic: &Param{Name: "value"}, Returns: sameAsFirst,
		Doc: "the first argument that is not null",
	},
	{
		Name: "keys", Params: []Param{p("map", nil)}, Return: tStrArr,
		Doc: "the keys of a map or JSON object",
	},
	{
		Name: "values", Params: []Param{p("map", nil)},
		Returns: func(args []*mdm.Type) *mdm.Type {
			if len(args) == 0 {
				return tAnyArr
			}
			if e := args[0].Elem_(); e != nil {
				return mdm.ArrayOf(e)
			}
			return tAnyArr
		},
		Doc: "the values of a map or JSON object",
	},
	// min and max appear in the corpus but in no published reference.
	{Name: "min", Params: []Param{p("value", tFloat)}, Variadic: &Param{Name: "value", Type: tFloat}, Return: tFloat, Doc: "the smallest of its arguments"},
	{Name: "max", Params: []Param{p("value", tFloat)}, Variadic: &Param{Name: "value", Type: tFloat}, Return: tFloat, Doc: "the largest of its arguments"},
}

// stringFuncs are all pure: text in, answer out.
// aliasFuncs are unqualified spellings that appear in the corpus. `ilike` without its
// namespace occurs once, in insights/headers/gmail_autoforward.yml — Sublime validates
// their own corpus, so it resolves for them, and rejecting it here would fail a rule that
// demonstrably runs.
var aliasFuncs = []*Func{
	{Name: "ilike", Params: []Param{p("input", tStr), p("pattern", tStr)}, Variadic: &Param{Name: "pattern", Type: tStr}, Return: tBool, Doc: "unqualified alias for strings.ilike"},
	{Name: "like", Params: []Param{p("input", tStr), p("pattern", tStr)}, Variadic: &Param{Name: "pattern", Type: tStr}, Return: tBool, Doc: "unqualified alias for strings.like"},
}

var stringFuncs = []*Func{
	{Name: "strings.concat", Params: []Param{p("value", tStr)}, Variadic: &Param{Name: "value", Type: tStr}, Return: tStr, Doc: "the arguments joined together"},

	{Name: "strings.contains", Params: []Param{p("source", tStr), p("substring", tStr)}, Variadic: &Param{Name: "substring", Type: tStr}, Return: tBool, Doc: "whether the source contains any of the substrings"},
	{Name: "strings.icontains", Params: []Param{p("source", tStr), p("substring", tStr)}, Variadic: &Param{Name: "substring", Type: tStr}, Return: tBool, Doc: "case-insensitive contains"},

	{Name: "strings.starts_with", Params: []Param{p("source", tStr), p("prefix", tStr)}, Variadic: &Param{Name: "prefix", Type: tStr}, Return: tBool, Doc: "whether the source begins with any of the prefixes"},
	{Name: "strings.istarts_with", Params: []Param{p("source", tStr), p("prefix", tStr)}, Variadic: &Param{Name: "prefix", Type: tStr}, Return: tBool, Doc: "case-insensitive starts_with"},

	{Name: "strings.ends_with", Params: []Param{p("source", tStr), p("suffix", tStr)}, Variadic: &Param{Name: "suffix", Type: tStr}, Return: tBool, Doc: "whether the source ends with any of the suffixes"},
	{Name: "strings.iends_with", Params: []Param{p("source", tStr), p("suffix", tStr)}, Variadic: &Param{Name: "suffix", Type: tStr}, Return: tBool, Doc: "case-insensitive ends_with"},

	{Name: "strings.like", Params: []Param{p("input", tStr), p("pattern", tStr)}, Variadic: &Param{Name: "pattern", Type: tStr}, Return: tBool, Doc: "glob match over the whole string, with * and ?"},
	{Name: "strings.ilike", Params: []Param{p("input", tStr), p("pattern", tStr)}, Variadic: &Param{Name: "pattern", Type: tStr}, Return: tBool, Doc: "case-insensitive like"},

	{Name: "strings.count", Params: []Param{p("source", tStr), p("substring", tStr)}, Return: tInt, Doc: "how many times the substring occurs"},
	{Name: "strings.icount", Params: []Param{p("source", tStr), p("substring", tStr)}, Return: tInt, Doc: "case-insensitive count"},

	{Name: "strings.levenshtein", Params: []Param{p("a", tStr), p("b", tStr)}, Return: tInt, Doc: "edit distance between two strings"},
	{Name: "strings.ilevenshtein", Params: []Param{p("a", tStr), p("b", tStr)}, Return: tInt, Doc: "case-insensitive edit distance"},

	// Undocumented but used 321 times: Unicode confusable folding, which is what makes
	// lookalike-domain detection work at all.
	{Name: "strings.replace_confusables", Params: []Param{p("input", tStr)}, Return: tStr, Doc: "homoglyphs folded to their ASCII lookalikes"},

	{Name: "strings.parse_domain", Params: []Param{p("text", tStr)}, Return: mdm.TypeOf(mdm.Domain{}), Doc: "a hostname split into its registrable parts"},
	{Name: "strings.parse_email", Params: []Param{p("text", tStr)}, Return: mdm.TypeOf(mdm.EmailAddress{}), Doc: "an address split into local part and domain"},
	{Name: "strings.parse_url", Params: []Param{p("text", tStr)}, Keywords: []Param{kw("strict", tBool, "true")}, Return: mdm.TypeOf(mdm.URL{}), Doc: "a URL split into its components"},
	{Name: "strings.parse_html", Params: []Param{p("input", tStr)}, Return: mdm.TypeOf(mdm.HTML{}), Doc: "a string parsed as HTML"},
	{Name: "strings.parse_json", Params: []Param{p("input", tStr)}, Return: mdm.JSON, Doc: "a string parsed as JSON"},
	{Name: "strings.parse_float", Params: []Param{p("input", tStr)}, Return: tFloat, Doc: "a string parsed as a number"},

	{
		Name: "strings.decode_base64", Params: []Param{p("text", tStr)},
		Keywords: []Param{kw("encodings", tStrArr, `["ascii","utf8"]`), kw("ignore_padding", tBool, "false"), kw("format", tStr, `"standard"`)},
		Return:   tStr, Doc: "base64 decoded, or null if it does not decode",
	},
	{
		Name: "strings.scan_base64", Params: []Param{p("text", tStr)},
		Keywords: []Param{kw("encodings", tStrArr, `["ascii","utf8"]`), kw("ignore_padding", tBool, "false"), kw("multiline", tBool, "true"), kw("format", tStr, `"standard"`)},
		Return:   tStrArr, Doc: "every base64 run found in the text, decoded",
	},
	{Name: "strings.decode_hex", Params: []Param{p("text", tStr)}, Return: tStr, Doc: "hex decoded"},
}

// regexFuncs use RE2 — specifically the Go flavour, which is exactly what this engine
// runs, so their behaviour matches Sublime's rather than approximating it.
var regexFuncs = []*Func{
	{Name: "regex.match", Params: []Param{p("input", tStr), p("pattern", tStr)}, Variadic: &Param{Name: "pattern", Type: tStr}, Return: tBool, Doc: "whole-string match against any pattern"},
	{Name: "regex.imatch", Params: []Param{p("input", tStr), p("pattern", tStr)}, Variadic: &Param{Name: "pattern", Type: tStr}, Return: tBool, Doc: "case-insensitive match"},
	{Name: "regex.contains", Params: []Param{p("input", tStr), p("pattern", tStr)}, Variadic: &Param{Name: "pattern", Type: tStr}, Return: tBool, Doc: "substring match against any pattern"},
	{Name: "regex.icontains", Params: []Param{p("input", tStr), p("pattern", tStr)}, Variadic: &Param{Name: "pattern", Type: tStr}, Return: tBool, Doc: "case-insensitive contains"},
	{Name: "regex.count", Params: []Param{p("input", tStr), p("pattern", tStr)}, Return: tInt, Doc: "how many times the pattern matches"},
	{Name: "regex.icount", Params: []Param{p("input", tStr), p("pattern", tStr)}, Return: tInt, Doc: "case-insensitive count"},
	{Name: "regex.extract", Params: []Param{p("input", tStr), p("pattern", tStr)}, Return: mdm.ArrayOf(mdm.TypeOf(mdm.RegexMatch{})), Doc: "every match, with its capture groups"},
	{Name: "regex.iextract", Params: []Param{p("input", tStr), p("pattern", tStr)}, Return: mdm.ArrayOf(mdm.TypeOf(mdm.RegexMatch{})), Doc: "case-insensitive extract"},
}

// hashFuncs are pure digests over text. Used by rules that want to compare a value
// without writing it down — an allowlist of sender domains that is not itself readable.
var hashFuncs = []*Func{
	{Name: "hash.sha256", Params: []Param{p("input", tStr)}, Return: tStr, Doc: "the SHA-256 of a string, hex encoded"},
	{Name: "hash.sha1", Params: []Param{p("input", tStr)}, Return: tStr, Doc: "the SHA-1 of a string, hex encoded"},
	{Name: "hash.md5", Params: []Param{p("input", tStr)}, Return: tStr, Doc: "the MD5 of a string, hex encoded"},
}

var htmlFuncs = []*Func{
	{Name: "html.xpath", Params: []Param{p("input", nil), p("query", tStr)}, Return: mdm.TypeOf(mdm.HTMLXPathResult{}), Doc: "the nodes an XPath query selects"},
}

// fileFuncs split between the parsers, which are pure, and the heavy analysis that needs
// a sandbox. The split is exactly where module 3 plugs in.
var fileFuncs = []*Func{
	{Name: "file.parse_html", Params: []Param{p("input", nil)}, Return: mdm.TypeOf(mdm.HTML{}), Doc: "a file parsed as HTML"},
	{Name: "file.parse_text", Params: []Param{p("input", nil)}, Keywords: []Param{kw("encodings", tStrArr, `["ascii","utf8"]`)}, Return: mdm.TypeOf(mdm.ParseTextOutput{}), Doc: "a file decoded to text"},
	{Name: "file.parse_eml", Params: []Param{p("input", nil)}, Return: mdm.TypeOf(mdm.MessageDataModel{}), Doc: "an attached message parsed into a full data model"},
	{Name: "file.parse_ics", Params: []Param{p("input", nil)}, Return: mdm.TypeOf(mdm.StrelkaICS{}), Doc: "a calendar invitation parsed"},

	{
		Name: "file.explode", Params: []Param{p("input", nil)},
		Return:     mdm.ArrayOf(mdm.TypeOf(mdm.FileExplodeOutput{})),
		Capability: enrich.CapFileExplode,
		Doc:        "a file recursively extracted and scanned, including by YARA",
	},
	{
		Name: "file.expand_archives", Params: []Param{p("input", nil)},
		Keywords:   []Param{kw("max_depth", tInt, "5")},
		Return:     mdm.TypeOf(mdm.ExpandArchivesResult{}),
		Capability: enrich.CapFileExpandArchives,
		Doc:        "nested archives extracted, without scanning",
	},
	{
		Name: "file.oletools", Params: []Param{p("input", nil)},
		Return: mdm.TypeOf(mdm.OleToolsOutput{}), Capability: enrich.CapFileOletools,
		Doc: "OLE and Office document analysis",
	},
	{
		Name: "file.html_screenshot", Params: []Param{p("input", nil)},
		Return: mdm.TypeOf(mdm.File{}), Capability: enrich.CapFileHTMLScreenshot,
		Doc: "a rendered screenshot of an HTML file",
	},
	{
		Name: "file.message_screenshot", Return: mdm.TypeOf(mdm.File{}),
		Capability: enrich.CapFileMessageScreenshot,
		Doc:        "a rendered screenshot of the message body",
	},
}

var mlFuncs = []*Func{
	{
		Name: "ml.link_analysis", Params: []Param{p("input", nil)},
		Keywords: []Param{kw("mode", tStr, `"default"`)},
		Return:   mdm.TypeOf(mdm.LinkAnalysisOutput{}), Capability: enrich.CapMLLinkAnalysis,
		Doc: "a link visited and classified",
	},
	{
		// The published signature says this returns an array, but every one of the 127
		// calls in the corpus reads `.brands` straight off the result. The corpus is what
		// actually runs, so it wins.
		Name: "ml.logo_detect", Params: []Param{p("input", nil)},
		Return: mdm.TypeOf(mdm.LogoDetectOutput{}), Capability: enrich.CapMLLogoDetect,
		Doc: "brand logos recognised in an image",
	},
	{
		Name: "ml.macro_classifier", Params: []Param{p("input", nil)},
		Return: mdm.TypeOf(mdm.MLMacrosOutput{}), Capability: enrich.CapMLMacroClassifier,
		Doc: "whether a document's macros look malicious",
	},
	{
		Name: "ml.nlu_classifier", Params: []Param{p("input", tStr)},
		Keywords: []Param{kw("display_name", tStr, ""), kw("subject", tStr, "")},
		Return:   mdm.TypeOf(mdm.NluResult{}), Capability: enrich.CapMLNLUClassifier,
		Doc: "intent, entity and topic classification of text",
	},
	{
		Name: "ml.attack_score", Return: mdm.TypeOf(mdm.AttackScore{}),
		Capability: enrich.CapMLAttackScore, Doc: "the model's overall attack score",
	},
}

var networkFuncs = []*Func{
	{
		Name: "network.whois", Params: []Param{p("domain", nil)},
		Return: mdm.TypeOf(mdm.WhoisOutput{}), Capability: enrich.CapNetworkWhois,
		Doc: "registration data for a domain",
	},
}

// profileFuncs need the organisation's message history, so they belong to the service
// rather than the library. Their results are relative to the time of the message being
// evaluated, which is what makes backtests honest.
var profileFuncs = []*Func{
	{Name: "profile.by_sender", Return: mdm.TypeOf(mdm.SenderProfile{}), Capability: enrich.CapProfileBySender, Doc: "history for this sender, keyed by address or domain"},
	{Name: "profile.by_sender_email", Return: mdm.TypeOf(mdm.SenderProfile{}), Capability: enrich.CapProfileBySenderEmail, Doc: "history for this exact address"},
	{Name: "profile.by_sender_domain", Return: mdm.TypeOf(mdm.SenderProfile{}), Capability: enrich.CapProfileBySenderDomain, Doc: "history for this sender domain"},
	{Name: "profile.by_reply_to", Return: mdm.TypeOf(mdm.SenderProfile{}), Capability: enrich.CapProfileByReplyTo, Doc: "history for the reply-to address"},
}

// betaFuncs are the beta namespace. Two of them are pure and implemented here; the rest
// need a model.
var betaFuncs = []*Func{
	// Pure: CIDR containment. One corpus rule is a 242 KB call to this over thousands of
	// ranges, which is why large literal sets compile to a prefix trie.
	{Name: "beta.ip_in", Params: []Param{p("ip", nil), p("range", tStr)}, Variadic: &Param{Name: "range", Type: tStr}, Return: tBool, Doc: "whether an address falls in any of the CIDR ranges"},
	{
		Name: "beta.scan_base64", Params: []Param{p("text", tStr)},
		Keywords: []Param{kw("encodings", tStrArr, `["ascii","utf8"]`), kw("ignore_padding", tBool, "false"), kw("multiline", tBool, "true"), kw("format", tStr, `"standard"`)},
		Return:   tStrArr, Doc: "every base64 run found in the text, decoded",
	},

	{Name: "beta.ocr", Params: []Param{p("input", nil)}, Return: mdm.TypeOf(mdm.OCROutput{}), Capability: enrich.CapBetaOCR, Doc: "text recognised in an image"},
	{Name: "beta.scan_qr", Params: []Param{p("input", nil)}, Return: mdm.TypeOf(mdm.QRScanOutput{}), Capability: enrich.CapBetaScanQR, Doc: "QR codes decoded from an image"},
	{Name: "beta.parse_exif", Params: []Param{p("input", nil)}, Return: mdm.TypeOf(mdm.ExifOutput{}), Capability: enrich.CapBetaParseExif, Doc: "embedded document and image metadata"},
	{Name: "beta.ml_topic", Params: []Param{p("input", tStr)}, Return: mdm.TypeOf(mdm.NluResult{}), Capability: enrich.CapBetaMLTopic, Doc: "topic classification of text"},
	{Name: "beta.ml_translate", Params: []Param{p("input", tStr)}, Return: mdm.TypeOf(mdm.TranslateOutput{}), Capability: enrich.CapBetaTranslate, Doc: "text translated to English"},
	{Name: "beta.ml_extract_sensitive_information", Params: []Param{p("input", tStr)}, Return: mdm.TypeOf(mdm.SensitiveInfoOutput{}), Capability: enrich.CapBetaExtractPII, Doc: "sensitive data extracted from text"},
	{Name: "beta.fuzzy_attack_score", Return: mdm.TypeOf(mdm.AttackScore{}), Capability: enrich.CapBetaFuzzyScore, Doc: "an approximate attack score"},
	// Nested beta namespaces. These appear only in the corpus, never in a reference, and
	// look like earlier homes for functions that later moved: beta.file.parse_ics is the
	// only way the corpus parses a calendar invitation, and beta.profile.by_reply_to has
	// no non-beta spelling at all.
	{Name: "beta.file.parse_ics", Params: []Param{p("input", nil)}, Return: mdm.TypeOf(mdm.ICSOutput{}), Doc: "a calendar invitation parsed into its events"},
	{Name: "beta.profile.by_reply_to", Return: mdm.TypeOf(mdm.SenderProfile{}), Capability: enrich.CapProfileByReplyTo, Doc: "history for the reply-to address"},

	{Name: "beta.whois", Params: []Param{p("domain", nil)}, Return: mdm.TypeOf(mdm.WhoisOutput{}), Capability: enrich.CapNetworkWhois, Doc: "deprecated alias for network.whois"},
	{Name: "beta.linkanalysis", Params: []Param{p("input", nil)}, Keywords: []Param{kw("mode", tStr, `"default"`)}, Return: mdm.TypeOf(mdm.LinkAnalysisOutput{}), Capability: enrich.CapMLLinkAnalysis, Doc: "deprecated alias for ml.link_analysis"},
}
