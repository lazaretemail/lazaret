// SPDX-License-Identifier: AGPL-3.0-only

// Command lazaret is the Lazaret engine's command line.
//
// It exists so that the engine is usable and checkable without deploying anything: parse a
// message, look at the model a rule would see, check a rule compiles. The service that
// wraps the same libraries is a separate module.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/lazaretemail/lazaret/eml"
	"github.com/lazaretemail/lazaret/lists"
	"github.com/lazaretemail/lazaret/ml"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/oletools"
	"github.com/lazaretemail/lazaret/orgconfig"
	"github.com/lazaretemail/lazaret/profile"
	"github.com/lazaretemail/lazaret/rdap"
	"github.com/lazaretemail/lazaret/render"
	"github.com/lazaretemail/lazaret/rules"
	"github.com/lazaretemail/lazaret/sensitive"
	"github.com/lazaretemail/lazaret/strelka"
	"github.com/lazaretemail/lazaret/yara"
)

const usage = `lazaret — open-source email security, compatible with Sublime's MQL

Usage:
  lazaret parse [-org config.yaml] [-raw] <message.eml>
        Parse a message and print its Message Data Model as JSON.

  lazaret lint [-rule] <rule.mql | ->
        Parse and type-check an MQL expression. Reports unknown fields and
        functions, argument mismatches, and the capabilities the rule needs.
        With -rule, also require that it evaluates to a boolean.

  lazaret run [-org config.yaml] [-lists dir] [-rdap] [-strelka addr] [-v]
              --rules <dir> <message.eml>
        Run a directory of detection content over a message and report what
        fired, what was suppressed, and what could not be decided.
        -rdap enables live RDAP lookups; it is off by default because running
        a tool over a message should not reach the network unasked.
        -strelka points at a Strelka frontend and enables file.explode, which
        unblocks more rules than any other single capability.

  lazaret rdap <domain | ip | ASnnn>
        Look up registration data over RDAP. Domains fall back to legacy WHOIS
        only for TLDs that publish no RDAP service; addresses and AS numbers
        use the RFC 9224 bootstrap registries and have no fallback.

  lazaret yara --rules <dir> <message.eml>
        Scan a message's attachments with YARA signatures. Needs a build with
        -tags yara; without it the command says so rather than reporting a
        clean scan.

  lazaret fmt <rule.mql | ->
        Reformat an MQL expression.

Message direction (type.inbound and friends) is defined relative to your own verified
domains, so -org is needed for it to be populated. Without it those fields stay null and
the reason is recorded in the model's _errors.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "parse":
		err = cmdParse(os.Args[2:])
	case "lint":
		err = cmdLint(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "rdap", "whois":
		err = cmdRDAP(os.Args[2:])
	case "yara":
		err = cmdYara(os.Args[2:])
	case "fmt":
		err = cmdFmt(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "lazaret: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "lazaret: %v\n", err)
		os.Exit(1)
	}
}

func cmdParse(args []string) error {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	orgPath := fs.String("org", "", "path to an organisation config, needed for type.inbound")
	includeRaw := fs.Bool("raw", false, "include attachment bytes in the output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("parse takes exactly one message file (or - for stdin)")
	}

	raw, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}

	opts := &eml.Options{}
	if *orgPath != "" {
		org, err := orgconfig.Load(*orgPath)
		if err != nil {
			return err
		}
		opts.Org = org
	}

	m, err := eml.Parse(raw, opts)
	if err != nil {
		return err
	}

	// Attachment bytes are omitted unless asked for: they are usually far larger than the
	// rest of the model, and dumping malware to a terminal helps nobody.
	if !*includeRaw {
		for _, a := range m.Attachments {
			a.Raw = nil
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(m)
}

func cmdLint(args []string) error {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	asRule := fs.Bool("rule", false, "require the expression to evaluate to a boolean")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("lint takes exactly one rule file (or - for stdin)")
	}

	src, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	text := string(src)

	checked, err := mql.Compile(text, &mql.CheckOptions{RequireBoolean: *asRule})
	if err != nil {
		if errs, ok := err.(mql.ErrorList); ok {
			fmt.Fprint(os.Stderr, errs.Render(text))
			return fmt.Errorf("%d problem(s)", len(errs))
		}
		return err
	}

	fmt.Printf("ok — evaluates to %s\n", checked.Type.Describe())

	// Accepted, but not by everyone. Reported here rather than refused at parse time:
	// the corpus contains real rules using these forms, and rejecting content people
	// run today would be the wrong kind of strictness. Someone writing new content
	// should still be told, because the divergence is invisible until the rule
	// reaches an engine that refuses it.
	for _, w := range mql.PortabilityWarnings(checked) {
		fmt.Printf("portability: %s\n", w.Message)
	}
	if len(checked.Lists) > 0 {
		fmt.Printf("lists: %s\n", strings.Join(checked.Lists, ", "))
	}
	if checked.NeedsEnrichment() {
		// Worth saying plainly: without these the rule cannot return a verdict, only an
		// "I do not know", and someone reading a clean run should not mistake the two.
		names := make([]string, len(checked.Capabilities))
		for i, c := range checked.Capabilities {
			names[i] = string(c)
		}
		fmt.Printf("needs: %s\n", strings.Join(names, ", "))
		fmt.Println("  (unavailable capabilities make this rule indeterminate, not a no-match)")
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	rulesDir := fs.String("rules", "", "directory of detection content (required)")
	orgPath := fs.String("org", "", "organisation config, needed for type.inbound and the $org_* lists")
	listsDir := fs.String("lists", "", "directory of list files, overriding the embedded copy")
	fetchLists := fs.Bool("fetch-lists", false, "download the ranked domain tables too large to embed (tranco, umbrella, alexa, majestic), cached on disk")
	enableRDAP := fs.Bool("rdap", false, "enable live RDAP lookups (network.whois, and the rdap.* extensions)")
	strelkaAddr := fs.String("strelka", "", "address of a Strelka frontend, enabling file.explode")
	historyPath := fs.String("history", "", "JSONL message history, enabling the profile.* family")
	renderAddr := fs.String("render", "", "base URL of a lazaret-render, enabling the screenshot capabilities")
	linkAnalysis := fs.Bool("link-analysis", false, "also enable ml.link_analysis, which makes the renderer visit links")
	mlAddr := fs.String("ml", "", "base URL of a lazaret-ml, enabling the model-backed capabilities")
	verbose := fs.Bool("v", false, "also report rules that could not be decided")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rulesDir == "" || fs.NArg() != 1 {
		return fmt.Errorf("run needs --rules <dir> and exactly one message file")
	}

	raw, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}

	var org *orgconfig.Config
	if *orgPath != "" {
		if org, err = orgconfig.Load(*orgPath); err != nil {
			return err
		}
	}

	// The published `$list` data is vendored, so the common case needs no flags and no
	// network: 22 of the 32 lists are compiled in, including
	// $high_trust_sender_root_domains, which gates 692 corpus rules on its own.
	resolver, err := lists.Embedded()
	if err != nil {
		return err
	}
	if *fetchLists {
		// Opt-in, like -rdap: a tool run over a message should not reach the network
		// unasked. Cached on disk afterwards, so this is slow once.
		if err := resolver.Fetch(context.Background(), nil); err != nil {
			return err
		}
	}
	if *listsDir != "" {
		if err := resolver.LoadDir(*listsDir); err != nil {
			return err
		}
	}
	resolver.AddOrgLists(org)

	engineOpts := &rules.Options{Lists: resolver, SkipDisabled: true}

	// Capability providers are composed rather than chosen: enabling one must not imply
	// claiming the others, or a rule needing a model would lose its file clause too.
	mux := mql.NewMux()
	var providers int

	// DLP needs no service and no model: every type the corpus names is a pattern, and
	// most carry a checksum. It is always on because there is nothing to configure.
	mux.Handle(sensitive.New(), sensitive.Capabilities()...)
	// Office document analysis, local like sensitive: a document is a zip or a
	// compound file, so the CLI answers file.oletools with no services running.
	mux.Handle(oletools.New(), oletools.Capabilities()...)
	providers++

	if *strelkaAddr != "" {
		client, err := strelka.Dial(&strelka.Options{Address: *strelkaAddr, Gatekeeper: true})
		if err != nil {
			return err
		}
		defer client.Close()
		mux.Handle(client, strelka.Capabilities()...)
		providers++
	}

	if *mlAddr != "" {
		// A capability with no model loaded reports unavailable, so the rule is
		// indeterminate rather than answered by a guess.
		mux.Handle(ml.New(&ml.Options{Address: *mlAddr}), ml.Capabilities()...)
		providers++
	}

	if *renderAddr != "" {
		// A screenshot is never read for itself: it is fed to beta.ocr, ml.logo_detect,
		// beta.scan_qr or beta.parse_exif. With Strelka also configured, -render is what
		// makes text-inside-an-image phishing visible to a text engine.
		rc := render.New(&render.Options{Address: *renderAddr})
		mux.Handle(rc, render.Capabilities()...)
		providers++

		if *linkAnalysis {
			// Separate from -render because it inverts the posture: screenshotting a
			// message needs no network, following its links is a deliberate outbound
			// request to somewhere an attacker chose. The renderer must be started
			// with -fetch for this to work.
			mux.Handle(rc.EnableLinkAnalysis(), render.LinkAnalysisCapability())
		}
	}

	if *historyPath != "" {
		// profile.* is 898 corpus calls and the second largest capability after the ML
		// classifier. Results are relative to the message being evaluated, never to
		// now, so running this over old mail gives the verdict that mail would have got.
		store, err := profile.LoadFile(*historyPath)
		if err != nil {
			return err
		}
		mux.Handle(profile.New(store), profile.Capabilities()...)
		providers++

		// $sender_emails and $sender_domains mean "addresses we have heard from", which
		// is the same history by another name.
		resolver.Add(lists.NewSet("sender_emails", store.SenderEmails()))
		resolver.Add(lists.NewSet("sender_domains", store.SenderDomains()))
	}

	if *enableRDAP {
		mux.Handle(rdap.New(nil), rdap.Capabilities()...)
		providers++

		// The rdap.* extensions are not part of Sublime's language, so they exist only
		// on a registry that has been extended with them.
		reg, err := rdap.ExtendedRegistry()
		if err != nil {
			return err
		}
		engineOpts.Registry = reg
	}

	if providers > 0 {
		// Wrapped in a cache, because MQL gives rules no way to share a result: around
		// 500 corpus rules write `file.explode(.)` for themselves, and every one of them
		// would otherwise scan the same attachment again. One message, one cache — an
		// enrichment is a pure function of its arguments within a single analysis, so
		// there is nothing to invalidate, and nothing is carried between messages.
		engineOpts.Enricher = mql.NewCache(mux)
	}

	engine, failures, err := rules.LoadPath(*rulesDir, engineOpts)
	if err != nil {
		return err
	}
	for _, f := range failures {
		fmt.Fprintf(os.Stderr, "skipped %v\n", f)
	}

	msg, err := eml.Parse(raw, &eml.Options{Org: org})
	if err != nil {
		return err
	}

	report := engine.Run(context.Background(), msg)
	printReport(report, engine, resolver, *verbose)
	return nil
}

func printReport(report *rules.Report, engine *rules.Engine, resolver *lists.Resolver, verbose bool) {
	fmt.Printf("%d rules evaluated\n\n", engine.Len())

	if len(report.Flagged) > 0 {
		fmt.Printf("FLAGGED (%s)\n", cmp.Or(string(report.Severity()), "unrated"))
		for _, d := range report.Flagged {
			fmt.Printf("  %-10s %s\n", d.Entity.Severity, d.Entity.Name)
		}
		fmt.Println()
	}

	if report.Suppressed() {
		fmt.Println("SUPPRESSED by exclusion")
		for _, d := range report.Excluded {
			fmt.Printf("  %s\n", d.Entity.Name)
		}
		fmt.Println()
	}

	// The honest part of the report. A message is only clean if everything actually ran;
	// otherwise this is a partial inspection and saying "clean" would be a lie.
	if n := len(report.Indeterminate); n > 0 {
		fmt.Printf("UNDECIDED: %d rules could not run\n", n)
		for _, cap := range report.Missing {
			fmt.Printf("  missing %s\n", cap)
		}
		if verbose {
			for _, d := range report.Indeterminate {
				fmt.Printf("    %s\n", d.Entity.Name)
			}
		}
		fmt.Println()
	}

	if len(report.Errors) > 0 {
		fmt.Printf("ERRORS: %d rules failed\n", len(report.Errors))
		for _, d := range report.Errors {
			fmt.Printf("  %s: %v\n", d.Entity.Name, d.Err)
		}
		fmt.Println()
	}

	if missing := missingLists(engine, resolver); len(missing) > 0 {
		fmt.Printf("NOTE: %d referenced lists are not configured, so rules using them\n", len(missing))
		fmt.Printf("      are undecided rather than false. First few: %s\n\n",
			strings.Join(missing[:min(5, len(missing))], ", "))
	}

	switch {
	case len(report.Flagged) > 0 && report.Suppressed():
		fmt.Println("verdict: suppressed — detections fired but an exclusion matched")
	case len(report.Flagged) > 0:
		fmt.Println("verdict: malicious")
	case report.Clean():
		fmt.Println("verdict: clean")
	default:
		fmt.Println("verdict: inconclusive — nothing fired, but not everything could run")
	}
}

func missingLists(engine *rules.Engine, resolver *lists.Resolver) []string {
	var out []string
	for _, name := range engine.Lists() {
		if !resolver.Known(name) {
			out = append(out, name)
		}
	}
	return out
}

func cmdRDAP(args []string) error {
	fs := flag.NewFlagSet("rdap", flag.ExitOnError)
	noLegacy := fs.Bool("no-legacy", false, "fail rather than falling back to legacy WHOIS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("rdap takes exactly one domain, IP address or AS number")
	}

	client := rdap.New(&rdap.Options{DisableLegacyWHOIS: *noLegacy})
	ctx := context.Background()
	query := strings.TrimSpace(fs.Arg(0))

	// The object type is inferred from the query, the way rdap.org's own service does:
	// an address, an AS number, or otherwise a domain.
	var (
		out any
		err error
	)
	switch {
	case isASNQuery(query):
		n, parseErr := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(query), "AS"), 10, 32)
		if parseErr != nil {
			return fmt.Errorf("%q is not an AS number", query)
		}
		out, err = client.LookupASN(ctx, uint32(n))
	case isIPQuery(query):
		out, err = client.LookupIP(ctx, query)
	default:
		out, err = client.Lookup(ctx, query)
	}
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func isIPQuery(s string) bool {
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

func isASNQuery(s string) bool {
	s = strings.ToUpper(s)
	if rest, found := strings.CutPrefix(s, "AS"); found {
		_, err := strconv.ParseUint(rest, 10, 32)
		return err == nil
	}
	// A bare number is an AS number; a domain always has a dot and an address parses as
	// one, so there is nothing else it could be.
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

func cmdYara(args []string) error {
	fs := flag.NewFlagSet("yara", flag.ExitOnError)
	sigDir := fs.String("rules", "", "directory of YARA signatures (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sigDir == "" || fs.NArg() != 1 {
		return fmt.Errorf("yara needs --rules <dir> and exactly one message file")
	}
	if !yara.Available() {
		return yara.ErrUnsupported
	}

	raw, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	msg, err := eml.Parse(raw, nil)
	if err != nil {
		return err
	}

	scanner, err := yara.CompileDir(*sigDir)
	if err != nil {
		return err
	}
	defer scanner.Close()

	results, err := yara.ScanAttachments(scanner, msg)
	if err != nil {
		return err
	}

	fmt.Printf("%d signatures, %d attachments scanned\n\n", scanner.Count(), len(results))
	hits := 0
	for name, res := range results {
		for _, m := range res.Matches {
			hits++
			fmt.Printf("  %s: %s\n", name, m.Name)
			for k, v := range m.Meta {
				fmt.Printf("      %s = %s\n", k, v)
			}
		}
	}
	if hits == 0 {
		// Said plainly, because the honest caveat below changes what it means.
		fmt.Println("  no signatures matched")
	}
	fmt.Println("\nNote: attachments are scanned as delivered. Archives are not opened, so a")
	fmt.Println("      signature matching a file inside a zip will not fire until the")
	fmt.Println("      file-analysis module lands.")
	return nil
}

func cmdFmt(args []string) error {
	fs := flag.NewFlagSet("fmt", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("fmt takes exactly one rule file (or - for stdin)")
	}

	src, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	expr, err := mql.Parse(string(src))
	if err != nil {
		if errs, ok := err.(mql.ErrorList); ok {
			fmt.Fprint(os.Stderr, errs.Render(string(src)))
		}
		return fmt.Errorf("cannot format a rule that does not parse")
	}
	fmt.Println(expr)
	return nil
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// A rule file read from disk usually has a trailing newline; the parser does not care,
	// but trimming keeps `fmt` output stable.
	if strings.HasSuffix(path, ".mql") {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	return data, nil
}
