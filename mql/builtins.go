// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
)

// evalCall dispatches a function call.
//
// The array functions are handled first because they are not ordinary calls: their later
// arguments are expressions to be evaluated once per element, in a new scope. Everything
// else has its arguments evaluated normally and is then either computed here or handed to
// the enricher.
func (e *evaluator) evalCall(n *Call) (Value, error) {
	name := callName(n.Fn)
	fn, ok := e.reg.Lookup(name)
	if !ok {
		return NullValue, fmt.Errorf("mql: no function %q", name)
	}

	if fn.Scope == ScopeElement {
		return e.evalScoped(n, fn)
	}

	args := make([]Value, 0, len(n.Args))
	for _, a := range n.Args {
		v, err := e.eval(a)
		if err != nil {
			return NullValue, err
		}
		args = append(args, v)
	}
	var kwargs map[string]Value
	for _, kw := range n.Keywords {
		v, err := e.eval(kw.Value)
		if err != nil {
			return NullValue, err
		}
		if kwargs == nil {
			kwargs = make(map[string]Value, len(n.Keywords))
		}
		kwargs[kw.Name] = v
	}

	if fn.Capability != "" {
		return e.callEnricher(fn, args, kwargs)
	}
	return callPure(name, args, kwargs)
}

// callEnricher asks the configured enricher for something the message alone cannot answer.
//
// When it cannot be had, the result is null *and* the capability is recorded. That pairing
// is the whole point: the rule keeps evaluating, and the verdict it produces is later
// downgraded to indeterminate rather than being mistaken for a clean no-match.
func (e *evaluator) callEnricher(fn *Func, args []Value, kwargs map[string]Value) (Value, error) {
	// The profile.* family takes no arguments: `profile.by_sender` means the sender of
	// the message being evaluated, and the message is not something MQL can name. The
	// evaluator has it, so a capability function that declares no parameters is handed
	// the message as its argument. Nothing else in the surface is zero-argument, so this
	// does not silently change any other call.
	if len(fn.Params) == 0 && len(args) == 0 {
		args = []Value{e.root}
	}
	if e.enrich == nil {
		e.tracker.Record(fn.Capability)
		return NullValue, nil
	}
	// The Tracker goes into the context so an enricher can record a capability it
	// answered only partly — a successful call with no error to record. See
	// enrich.RecordPartial.
	// An expired deadline is an unavailable capability, not a failed evaluation.
	//
	// Checked before the call as well as after, so that once a message has run out
	// of time the remaining rules stop reaching for enrichment instead of each
	// waiting for their own refusal.
	if e.ctx.Err() != nil {
		e.tracker.Record(fn.Capability)
		return NullValue, nil
	}

	v, err := e.enrich.Enrich(enrich.WithTracker(e.ctx, e.tracker), fn.Capability, args, kwargs)
	if err != nil {
		// Unavailable, and out of time, are the same answer: we could not find out.
		// Treating a deadline as a hard error would throw away a partial analysis
		// that had already matched rules — and a message that took too long to
		// enrich is exactly the one somebody wants the partial verdict for.
		if errors.Is(err, enrich.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, context.Canceled) || e.ctx.Err() != nil {
			e.tracker.Record(fn.Capability)
			return NullValue, nil
		}
		return NullValue, fmt.Errorf("%s: %w", fn.Name, err)
	}
	return v, nil
}

// evalScoped runs the array functions: any, all, filter, map, distinct, sum, ratio.
//
// Each evaluates its body once per element with `.` bound to that element. The body is an
// unevaluated expression rather than a closure value, because MQL has no first-class
// functions — which is also why this cannot be expressed as an ordinary signature.
func (e *evaluator) evalScoped(n *Call, fn *Func) (Value, error) {
	if len(n.Args) == 0 {
		return NullValue, nil
	}
	src, err := e.eval(n.Args[0])
	if err != nil {
		return NullValue, err
	}

	// distinct and sum may be called with no body, over an array of scalars.
	var body Expr
	if len(n.Args) > 1 {
		body = n.Args[1]
	}

	name := callName(n.Fn)

	// An array that is *null* is not an array that is *empty*, and the difference decides
	// verdicts. `ml.nlu_classifier(...).topics` with no ML service is null, and the corpus
	// is full of `not any(ml...(...), ...)` written to exclude newsletters and benign
	// mail. Folding null to empty makes `any` false, `not any` true, and a brand
	// impersonation rule fires *because* the classifier was unavailable — the project's
	// one invariant inverted, and a real false positive rather than a lost detection.
	//
	// Which builtins propagate and which absorb is irregular, so each was measured against
	// Sublime's engine on 2026-09-18 rather than derived; see docs/SEMANTICS.md and
	// TestDifferentialNullArray.
	if src.IsNull() {
		switch name {
		case "any", "map", "ratio":
			return NullValue, nil
		case "all":
			// Vacuously true, as over an empty array.
			return TrueValue, nil
		case "filter", "distinct", "flatten":
			return ArrayValue(nil), nil
		}
		// sum falls through to the loop below and yields its zero.
	}
	elems := src.Elements()

	// Evaluating the body for one element, with the scope pushed and popped around it.
	run := func(elem Value) (Value, error) {
		e.scopes = append(e.scopes, elem)
		v, err := e.eval(body)
		e.scopes = e.scopes[:len(e.scopes)-1]
		return v, err
	}

	switch name {
	case "any", "all":
		wantAll := name == "all"
		sawNull := false
		for _, elem := range elems {
			v, err := run(elem)
			if err != nil {
				return NullValue, err
			}
			b, ok := v.AsBool()
			switch {
			case !ok:
				sawNull = true
			case wantAll && !b:
				return FalseValue, nil
			case !wantAll && b:
				return TrueValue, nil
			}
		}
		if sawNull {
			// An undecidable element leaves the answer undecided — unless a decisive
			// element was already found above, which is why this is checked last.
			return NullValue, nil
		}
		// `all` over an empty array is vacuously true, which is documented.
		return BoolValue(wantAll), nil

	case "filter":
		out := make([]Value, 0, len(elems))
		for _, elem := range elems {
			v, err := run(elem)
			if err != nil {
				return NullValue, err
			}
			if v.Truthy() {
				out = append(out, elem)
			}
		}
		return ArrayValue(out), nil

	case "map":
		out := make([]Value, 0, len(elems))
		for _, elem := range elems {
			v, err := run(elem)
			if err != nil {
				return NullValue, err
			}
			out = append(out, v)
		}
		return ArrayValue(out), nil

	case "distinct":
		seen := make(map[string]bool, len(elems))
		out := make([]Value, 0, len(elems))
		for _, elem := range elems {
			key := elem
			if body != nil {
				v, err := run(elem)
				if err != nil {
					return NullValue, err
				}
				key = v
			}
			k := key.String()
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, elem)
		}
		return ArrayValue(out), nil

	case "sum":
		var total float64
		isInt := true
		for _, elem := range elems {
			v := elem
			if body != nil {
				got, err := run(elem)
				if err != nil {
					return NullValue, err
				}
				v = got
			}
			f, ok := v.AsFloat()
			if !ok {
				continue // a null contributes nothing rather than poisoning the total
			}
			if v.Kind() != mdm.KindInt {
				isInt = false
			}
			total += f
		}
		if isInt {
			return IntValue(int64(total)), nil
		}
		return FloatValue(total), nil

	case "ratio":
		if len(elems) == 0 {
			// Documented: ratio over an empty array is null, not zero. A rule asking what
			// proportion of nothing matched has not learned anything.
			return NullValue, nil
		}
		matched := 0
		for _, elem := range elems {
			v, err := run(elem)
			if err != nil {
				return NullValue, err
			}
			if v.Truthy() {
				matched++
			}
		}
		return FloatValue(float64(matched) / float64(len(elems))), nil
	}
	return NullValue, nil
}

// callPure computes a function that needs nothing but its arguments.
func callPure(name string, args []Value, kwargs map[string]Value) (Value, error) {
	switch name {
	case "length":
		return builtinLength(arg(args, 0)), nil
	case "coalesce":
		for _, a := range args {
			if !a.IsNull() {
				return a, nil
			}
		}
		return NullValue, nil
	case "flatten":
		return ArrayValue(flattenValues(arg(args, 0))), nil
	case "keys":
		return mapKeys(arg(args, 0)), nil
	case "values":
		return mapValues(arg(args, 0)), nil
	case "min", "max":
		return minMax(name, args), nil
	}

	if strings.HasPrefix(name, "strings.") || name == "ilike" || name == "like" {
		return stringFunc(name, args, kwargs)
	}
	if strings.HasPrefix(name, "regex.") {
		return regexFunc(name, args)
	}
	if strings.HasPrefix(name, "hash.") {
		return hashFunc(name, args), nil
	}
	if name == "beta.ip_in" {
		return ipIn(args), nil
	}
	switch name {
	case "html.xpath":
		query, ok := arg(args, 1).AsString()
		if !ok {
			return NullValue, nil
		}
		return xpathQuery(arg(args, 0), query)
	case "strings.parse_html", "file.parse_html":
		return parseHTMLValue(arg(args, 0)), nil
	case "file.parse_text":
		// Whatever text can be recovered from the input. Real decoding of arbitrary file
		// formats is the file-analysis module's job; a value that is already text needs
		// none of it.
		s, ok := htmlSource(arg(args, 0))
		if !ok {
			return NullValue, nil
		}
		return FromGo(&mdm.ParseTextOutput{Text: mdm.Ptr(s)}), nil
	}
	if name == "beta.scan_base64" {
		return stringFunc("strings.scan_base64", args, kwargs)
	}

	// A pure function the evaluator has not implemented yet. This is reported rather than
	// silently returning null, because unlike a missing capability it is our gap, not the
	// deployment's, and a rule quietly failing to fire would hide it.
	return NullValue, fmt.Errorf("mql: %s is not implemented", name)
}

func arg(args []Value, i int) Value {
	if i < len(args) {
		return args[i]
	}
	return NullValue
}

// builtinLength implements the documented and deliberately irregular length rules: null on
// a string is null, but null on an array or a map is 0.
func builtinLength(v Value) Value {
	switch v.Kind() {
	case mdm.KindString, mdm.KindBytes:
		s, _ := v.AsString()
		return IntValue(int64(len([]rune(s))))
	case mdm.KindArray, mdm.KindMap:
		n, _ := v.Len()
		return IntValue(int64(n))
	case mdm.KindJSON:
		if n, ok := v.Len(); ok {
			return IntValue(int64(n))
		}
		return NullValue
	case mdm.KindNull:
		// Which answer null gives depends on what was expected, and at run time that is
		// no longer visible. Null is the safer of the two: it propagates rather than
		// asserting a length of zero for something that may have been a string.
		return NullValue
	}
	return NullValue
}

func flattenValues(v Value) []Value {
	var out []Value
	var walk func(Value)
	walk = func(v Value) {
		if v.Kind() == mdm.KindArray {
			for _, e := range v.Elements() {
				walk(e)
			}
			return
		}
		out = append(out, v)
	}
	walk(v)
	return out
}

func mapKeys(v Value) Value {
	entries := v.Entries()
	if entries == nil {
		return ArrayValue(nil)
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	// Sorted, so that a rule reading keys() gets the same answer on every run. Map
	// iteration order would otherwise make some rules non-deterministic.
	sortStrings(keys)
	out := make([]Value, len(keys))
	for i, k := range keys {
		out[i] = StringValue(k)
	}
	return ArrayValue(out)
}

func mapValues(v Value) Value {
	entries := v.Entries()
	if entries == nil {
		return ArrayValue(nil)
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]Value, len(keys))
	for i, k := range keys {
		out[i] = entries[k]
	}
	return ArrayValue(out)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func minMax(name string, args []Value) Value {
	var best Value = NullValue
	for _, a := range args {
		if a.IsNull() {
			continue
		}
		if best.IsNull() {
			best = a
			continue
		}
		cmp, ok := a.Compare(best)
		if !ok {
			continue
		}
		if (name == "min" && cmp < 0) || (name == "max" && cmp > 0) {
			best = a
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// strings
// ---------------------------------------------------------------------------

func stringFunc(name string, args []Value, kwargs map[string]Value) (Value, error) {
	source, haveSource := arg(args, 0).AsString()

	// Variadic needles. The documented rule is that a null source, or every needle being
	// null, yields null — a partially null argument list does not.
	needles := make([]string, 0, max(len(args)-1, 0))
	anyNeedle := false
	for _, a := range args[min(1, len(args)):] {
		if s, ok := a.AsString(); ok {
			needles = append(needles, s)
			anyNeedle = true
		}
	}

	switch name {
	case "strings.concat":
		var b strings.Builder
		for _, a := range args {
			s, ok := a.AsString()
			if !ok {
				// Concatenating with null yields null: the corpus relies on this to skip
				// a comparison entirely rather than match against a partial string.
				return NullValue, nil
			}
			b.WriteString(s)
		}
		return StringValue(b.String()), nil

	case "strings.contains", "strings.icontains",
		"strings.starts_with", "strings.istarts_with",
		"strings.ends_with", "strings.iends_with",
		"strings.like", "strings.ilike", "like", "ilike":
		if !haveSource || !anyNeedle {
			return NullValue, nil
		}
		fold := strings.Contains(name, ".i") || name == "ilike"
		hay := source
		if fold {
			hay = strings.ToLower(source)
		}
		for _, needle := range needles {
			if fold {
				needle = strings.ToLower(needle)
			}
			var hit bool
			switch {
			case strings.HasSuffix(name, "like"):
				hit = globMatch(hay, needle)
			case strings.Contains(name, "starts_with"):
				hit = strings.HasPrefix(hay, needle)
			case strings.Contains(name, "ends_with"):
				hit = strings.HasSuffix(hay, needle)
			default:
				hit = strings.Contains(hay, needle)
			}
			if hit {
				return TrueValue, nil
			}
		}
		return FalseValue, nil

	case "strings.count", "strings.icount":
		needle, ok := arg(args, 1).AsString()
		if !haveSource || !ok {
			return NullValue, nil
		}
		if name == "strings.icount" {
			source, needle = strings.ToLower(source), strings.ToLower(needle)
		}
		if needle == "" {
			return IntValue(0), nil
		}
		return IntValue(int64(strings.Count(source, needle))), nil

	case "strings.levenshtein", "strings.ilevenshtein":
		a, aok := arg(args, 0).AsString()
		b, bok := arg(args, 1).AsString()
		if !aok || !bok {
			return NullValue, nil
		}
		if name == "strings.ilevenshtein" {
			a, b = strings.ToLower(a), strings.ToLower(b)
		}
		return IntValue(int64(editDistance(a, b))), nil

	case "strings.replace_confusables":
		if !haveSource {
			return NullValue, nil
		}
		return StringValue(foldConfusables(source)), nil

	case "strings.parse_domain":
		if !haveSource {
			return NullValue, nil
		}
		return goValue(mdm.ParseDomain(source)), nil

	case "strings.parse_email":
		if !haveSource {
			return NullValue, nil
		}
		return goValue(mdm.ParseEmailAddress(source)), nil

	case "strings.parse_url":
		if !haveSource {
			return NullValue, nil
		}
		strict := true
		if v, ok := kwargs["strict"]; ok {
			if b, ok := v.AsBool(); ok {
				strict = b
			}
		}
		return goValue(mdm.ParseURL(source, strict)), nil

	case "strings.parse_json":
		if !haveSource {
			return NullValue, nil
		}
		var decoded any
		if err := json.Unmarshal([]byte(source), &decoded); err != nil {
			// Documented: unparseable JSON yields null rather than an error.
			return NullValue, nil
		}
		return JSONValue(decoded), nil

	case "strings.parse_float":
		if !haveSource {
			return NullValue, nil
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(source), 64)
		if err != nil {
			return NullValue, nil
		}
		return FloatValue(f), nil

	case "strings.decode_hex":
		if !haveSource {
			return NullValue, nil
		}
		raw, err := hex.DecodeString(strings.TrimSpace(source))
		if err != nil {
			return NullValue, nil
		}
		return StringValue(string(raw)), nil

	case "strings.decode_base64":
		if !haveSource {
			return NullValue, nil
		}
		decoded, ok := decodeBase64(source, kwargs)
		if !ok {
			return NullValue, nil
		}
		return StringValue(decoded), nil

	case "strings.scan_base64":
		if !haveSource {
			return NullValue, nil
		}
		var out []Value
		for _, candidate := range base64Runs(source) {
			if decoded, ok := decodeBase64(candidate, kwargs); ok && isMostlyPrintable(decoded) {
				out = append(out, StringValue(decoded))
			}
		}
		// Documented: finding nothing yields an empty array, not null.
		return ArrayValue(out), nil
	}
	return NullValue, fmt.Errorf("mql: %s is not implemented", name)
}

// globMatch implements the documented wildcard syntax: `*` for any run of characters and
// `?` for exactly one, matched against the whole string.
//
// No escape mechanism is documented, so there is none — recorded as inferred in
// docs/SEMANTICS.md. A pattern wanting a literal asterisk cannot say so, and that is
// upstream's decision rather than ours to fix.
func globMatch(s, pattern string) bool {
	sr, pr := []rune(s), []rune(pattern)
	// Iterative backtracking rather than recursion: patterns come from rule text, and
	// "*a*a*a*a*b" against a long body should not cost exponential time.
	var si, pi, starP, starS int
	starP = -1
	for si < len(sr) {
		switch {
		case pi < len(pr) && (pr[pi] == '?' || pr[pi] == sr[si]):
			si++
			pi++
		case pi < len(pr) && pr[pi] == '*':
			starP, starS = pi, si
			pi++
		case starP >= 0:
			starS++
			si, pi = starS, starP+1
		default:
			return false
		}
	}
	for pi < len(pr) && pr[pi] == '*' {
		pi++
	}
	return pi == len(pr)
}

// decodeBase64 tries the encodings a rule might mean. Padding is frequently absent in
// obfuscated payloads, which is what the ignore_padding option is for.
func decodeBase64(s string, kwargs map[string]Value) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}

	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding}
	if v, ok := kwargs["format"]; ok {
		if f, ok := v.AsString(); ok && (f == "url" || f == "urlsafe") {
			encodings = []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding}
		}
	}
	if v, ok := kwargs["ignore_padding"]; ok {
		if b, ok := v.AsBool(); ok && b {
			s = strings.TrimRight(s, "=")
			encodings = []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding}
		}
	}

	for _, enc := range encodings {
		if raw, err := enc.DecodeString(s); err == nil {
			return string(raw), true
		}
	}
	return "", false
}

// base64Pattern finds runs that could be base64. Deliberately loose: the cost of a false
// candidate is one failed decode, while missing one means missing the payload.
var base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

func base64Runs(s string) []string { return base64Pattern.FindAllString(s, -1) }

// isMostlyPrintable filters decodes that produced binary noise. Without it, scanning a
// long body yields a great deal of nothing.
func isMostlyPrintable(s string) bool {
	if s == "" {
		return false
	}
	printable := 0
	for _, r := range s {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	return float64(printable)/float64(len([]rune(s))) > 0.85
}

// goValue wraps a pointer from the data model, mapping a nil pointer to null.
func goValue[T any](p *T) Value {
	if p == nil {
		return NullValue
	}
	return FromGo(p)
}

// ---------------------------------------------------------------------------
// regex
// ---------------------------------------------------------------------------

// regexCache compiles each pattern once. Rules re-evaluate the same patterns against every
// message, and compiling a regular expression is far more expensive than running one.
var regexCache = newSyncMap[string, *regexp.Regexp]()

func compilePattern(pattern string, fold bool) (*regexp.Regexp, error) {
	key := pattern
	if fold {
		key = "(?i)" + pattern
	}
	if re, ok := regexCache.Load(key); ok {
		return re, nil
	}
	re, err := regexp.Compile(key)
	if err != nil {
		return nil, err
	}
	regexCache.Store(key, re)
	return re, nil
}

func regexFunc(name string, args []Value) (Value, error) {
	input, ok := arg(args, 0).AsString()
	if !ok {
		// Documented for match/imatch, and applied to the whole module for consistency.
		return NullValue, nil
	}
	fold := strings.HasPrefix(name, "regex.i")

	patterns := make([]string, 0, max(len(args)-1, 0))
	for _, a := range args[min(1, len(args)):] {
		if s, ok := a.AsString(); ok {
			patterns = append(patterns, s)
		}
	}
	if len(patterns) == 0 {
		return NullValue, nil
	}

	switch name {
	case "regex.match", "regex.imatch", "regex.contains", "regex.icontains":
		whole := strings.HasSuffix(name, "match")
		for _, p := range patterns {
			if whole {
				// match is anchored at both ends; contains is not.
				p = `\A(?:` + p + `)\z`
			}
			re, err := compilePattern(p, fold)
			if err != nil {
				return NullValue, fmt.Errorf("%s: %w", name, err)
			}
			if re.MatchString(input) {
				return TrueValue, nil
			}
		}
		return FalseValue, nil

	case "regex.count", "regex.icount":
		re, err := compilePattern(patterns[0], fold)
		if err != nil {
			return NullValue, fmt.Errorf("%s: %w", name, err)
		}
		return IntValue(int64(len(re.FindAllString(input, -1)))), nil

	case "regex.extract", "regex.iextract":
		re, err := compilePattern(patterns[0], fold)
		if err != nil {
			return NullValue, fmt.Errorf("%s: %w", name, err)
		}
		names := re.SubexpNames()
		var out []Value
		for _, m := range re.FindAllStringSubmatch(input, -1) {
			match := &mdm.RegexMatch{
				FullMatch:   m[0],
				Groups:      make([]string, 0, len(m)-1),
				NamedGroups: map[string]string{},
			}
			for i, g := range m[1:] {
				// Documented: a group that did not participate is "", never null.
				match.Groups = append(match.Groups, g)
				if n := names[i+1]; n != "" {
					match.NamedGroups[n] = g
				}
			}
			out = append(out, FromGo(match))
		}
		return ArrayValue(out), nil
	}
	return NullValue, fmt.Errorf("mql: %s is not implemented", name)
}

// ---------------------------------------------------------------------------
// hash and network helpers
// ---------------------------------------------------------------------------

func hashFunc(name string, args []Value) Value {
	s, ok := arg(args, 0).AsString()
	if !ok {
		return NullValue
	}
	switch name {
	case "hash.sha256":
		sum := sha256.Sum256([]byte(s))
		return StringValue(hex.EncodeToString(sum[:]))
	case "hash.sha1":
		sum := sha1.Sum([]byte(s))
		return StringValue(hex.EncodeToString(sum[:]))
	case "hash.md5":
		sum := md5.Sum([]byte(s))
		return StringValue(hex.EncodeToString(sum[:]))
	}
	return NullValue
}

// prefixCache turns a rule's CIDR list into a parsed set once.
//
// One rule in the corpus is a 242 KB call to beta.ip_in over thousands of ranges. Parsing
// those on every message would dominate the whole evaluation.
var prefixCache = newSyncMap[string, []netip.Prefix]()

func ipIn(args []Value) Value {
	target := arg(args, 0)

	// The address may be given as a string or as an IP object from the model.
	text, ok := target.AsString()
	if !ok {
		if inner := target.Field("ip"); !inner.IsNull() {
			text, ok = inner.AsString()
		}
	}
	if !ok {
		return NullValue
	}
	addr, err := netip.ParseAddr(strings.Trim(text, "[]"))
	if err != nil {
		return NullValue
	}
	addr = addr.Unmap()

	rest := args[min(1, len(args)):]
	key := cidrKey(rest)
	prefixes, cached := prefixCache.Load(key)
	if !cached {
		prefixes = make([]netip.Prefix, 0, len(rest))
		for _, a := range rest {
			s, ok := a.AsString()
			if !ok {
				continue
			}
			if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
				prefixes = append(prefixes, p)
			} else if one, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
				prefixes = append(prefixes, netip.PrefixFrom(one, one.BitLen()))
			}
		}
		prefixCache.Store(key, prefixes)
	}

	for _, p := range prefixes {
		if p.Contains(addr) {
			return TrueValue
		}
	}
	return FalseValue
}

// cidrKey identifies an argument list cheaply. The ranges in a rule are literals, so the
// first and last plus the count distinguish one rule's list from another's without hashing
// a quarter of a megabyte on every message.
func cidrKey(args []Value) string {
	if len(args) == 0 {
		return ""
	}
	first, _ := args[0].AsString()
	last, _ := args[len(args)-1].AsString()
	return strconv.Itoa(len(args)) + "\x00" + first + "\x00" + last
}

// foldConfusables maps homoglyphs onto the ASCII they imitate.
//
// This is what lookalike-domain detection rests on — 321 uses in the corpus — and the
// table below covers the substitutions that actually appear in attacks: Cyrillic and Greek
// letters that render identically to Latin ones, plus full-width forms. It is not the
// complete Unicode confusables set, and it is marked as partial rather than pretending
// otherwise.
var confusables = map[rune]rune{
	// Cyrillic
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
	'і': 'i', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ց': 'g', 'ᴍ': 'm',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y', 'І': 'I', 'Ј': 'J',
	// Greek
	'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'κ': 'k', 'ι': 'i',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
	'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	// Latin lookalikes and marks
	'ı': 'i', 'ł': 'l', 'ø': 'o', 'ɑ': 'a', 'ɡ': 'g', 'ʏ': 'y', 'ᴜ': 'u',
	// Punctuation that stands in for the separators in a hostname. Full-width forms are
	// handled by the offset rule below rather than listed here.
	'‐': '-', '‑': '-', '‒': '-', '–': '-', '—': '-', '․': '.', '。': '.', '﹒': '.',
}

func foldConfusables(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if mapped, ok := confusables[r]; ok {
			b.WriteRune(mapped)
			continue
		}
		// Full-width forms map back to ASCII by a fixed offset.
		if r >= 0xFF01 && r <= 0xFF5E {
			b.WriteRune(r - 0xFEE0)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
