// SPDX-License-Identifier: AGPL-3.0-only

// Command lazaret-engine is the API and pipeline service — module 2.
//
// It embeds the root module's libraries and adds everything that needs state: message
// history, sender profiles, the action log, hunt, and the HTTP surface. Module 1 is a
// library and a CLI that forget everything between runs; this is the thing that
// remembers, which is what makes profile.* answerable and hunt possible at all.
//
// Storage follows docs/ADR-001-storage.md: Postgres for relational state and the
// DuckLake catalog, Parquet in the blob store for the corpus, DuckDB linked in for
// hunt. This is the one cgo dependency in the tree and it stays here.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lazaretemail/lazaret/ml"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/oletools"
	"github.com/lazaretemail/lazaret/orgconfig"
	"github.com/lazaretemail/lazaret/profile"
	"github.com/lazaretemail/lazaret/rdap"
	"github.com/lazaretemail/lazaret/render"
	"github.com/lazaretemail/lazaret/rules"
	"github.com/lazaretemail/lazaret/sensitive"
	"github.com/lazaretemail/lazaret/services/engine/store"
	"github.com/lazaretemail/lazaret/strelka"
	"github.com/lazaretemail/lazaret/telemetry"
	"google.golang.org/grpc"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "lazaret-engine: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr     = flag.String("addr", ":8700", "listen address")
		pgConn   = flag.String("postgres", envOr("LAZARET_POSTGRES", ""), "postgres connection string")
		dataPath = flag.String("data", envOr("LAZARET_DATA", "./data/corpus"), "DuckLake data path: a directory or an s3:// URL")
		rulesDir = flag.String("rules", envOr("LAZARET_RULES", ""), "directory of detection content (required)")
		orgPath  = flag.String("org", envOr("LAZARET_ORG", ""), "organisation config")
		tenant   = flag.String("tenant", envOr("LAZARET_TENANT", "default"), "default tenant id")

		strelkaAddr  = flag.String("strelka", envOr("LAZARET_STRELKA", ""), "Strelka frontend address")
		renderAddr   = flag.String("render", envOr("LAZARET_RENDER", ""), "lazaret-render base URL")
		mlAddr       = flag.String("ml", envOr("LAZARET_ML", ""), "lazaret-ml base URL")
		linkAnalysis = flag.Bool("link-analysis", envOr("LAZARET_LINK_ANALYSIS", "") != "",
			"enable ml.link_analysis; the renderer must allow fetching. Also settable "+
				"with LAZARET_LINK_ANALYSIS, so a compose overlay can change it without "+
				"restating the whole command — an overlay that restates a command "+
				"silently drops every flag added to the base file afterwards")
		// On by default here, unlike the CLI. The reasoning differs: running a tool
		// over one message should not reach the network unasked, but a server whose
		// job is to process mail continuously has already accepted that, and
		// network.whois gates 103 rules. -rdap=false turns it off for an air-gapped
		// deployment.
		// Looking again at mail that has already been delivered. Both default on:
		// attribution lags delivery by hours, so a deployment that only judges mail
		// on the way in is permanently behind, and neither of these acts on its own
		// — they file findings a person reviews.
		retroSweep = flag.Bool("retro-sweep", envOr("LAZARET_RETRO_SWEEP", "1") != "",
			"when new detection content arrives, check it against mail already delivered")
		retroWindow = flag.Duration("retro-window", envDuration("LAZARET_RETRO_WINDOW", 30*24*time.Hour),
			"how far back a retrospective sweep looks")
		linkWatch = flag.Bool("link-watch", envOr("LAZARET_LINK_WATCH", "1") != "",
			"re-visit links from delivered mail and report ones that changed; needs "+
				"-render and -link-analysis")

		maxAnalyses = flag.Int("max-concurrent-analyses", envInt("LAZARET_MAX_ANALYSES", 0),
			"how many messages may be analysed at once; 0 derives one from the machine")
		analysisQueueWait = flag.Duration("analysis-queue-wait", 30*time.Second,
			"how long a message waits for a slot before the engine says it is busy")
		ruleConcurrency = flag.Int("rule-concurrency", envInt("LAZARET_RULE_CONCURRENCY", 0),
			"how many rules evaluate at once; 0 uses the measured default")
		enableRDAP = flag.Bool("rdap", true, "resolve network.whois over RDAP; -rdap=false for an air-gapped deployment")

		analysisTimeout = flag.Duration("analysis-timeout", 120*time.Second,
			"how long one message may spend being analysed; enrichment that overruns "+
				"reports unavailable and its rules report indeterminate, rather than the "+
				"message failing. A ceiling for pathological mail, not a target: a real "+
				"marketing email with nine tracking links takes about thirty seconds with "+
				"link analysis on, and the old default of thirty cut it off partway — after "+
				"which every capability the evaluator reached next was reported missing, "+
				"making working services look broken")
		rawPath    = flag.String("raw", envOr("LAZARET_RAW", "./data/raw"), "where the original bytes of ingested messages are held; quarantine removes a message from the mailbox, so this copy is what makes releasing it possible")
		s3Endpoint = flag.String("s3-endpoint", envOr("LAZARET_S3_ENDPOINT", ""), "blob store endpoint")
		// Garage's default region is "garage", not "us-east-1". SigV4 signs the
		// region into the request, so getting it wrong is not cosmetic — the server
		// rejects the signature with AuthorizationHeaderMalformed, which reads like
		// a credentials problem and is not one.
		s3Region = flag.String("s3-region", envOr("LAZARET_S3_REGION", "us-east-1"), "blob store region; Garage's default is \"garage\"")
		s3Key    = flag.String("s3-key", envFileOr("LAZARET_S3_KEY", ""),
			"blob store access key; LAZARET_S3_KEY_FILE reads it from a file instead")
		s3Secret = flag.String("s3-secret", envFileOr("LAZARET_S3_SECRET", ""),
			"blob store secret key; LAZARET_S3_SECRET_FILE reads it from a file instead")
		s3SSL = flag.Bool("s3-ssl", false, "use TLS to the blob store")

		compactEvery = flag.Duration("compact-every", 6*time.Hour, "how often to merge DuckLake's small files; 0 disables")
		maxBody      = flag.Int64("max-body", 64<<20, "maximum request body")
		secretKey    = flag.String("secret-key", envOr("LAZARET_SECRET_KEY", ""),
			"32-byte hex key encrypting mailbox credentials at rest; generated into "+
				"-state on first start when empty")
		publicURL = flag.String("public-url", envOr("LAZARET_PUBLIC_URL", ""),
			"where this deployment is reachable from the internet, e.g. "+
				"https://lazaret.example.com. Everything needing a public callback "+
				"derives its own from this — currently the Microsoft 365 notification "+
				"endpoint. Empty means Microsoft is polled instead, which needs no "+
				"inbound path and is the right answer for most deployments")
		stateDir = flag.String("state", envOr("LAZARET_STATE", "/var/lib/lazaret/state"),
			"directory for things generated on first start: the credential key and the "+
				"mail connector's API token. Back it up; losing the key means re-entering "+
				"every mailbox credential")

		noAuth     = flag.Bool("no-auth", false, "DISABLE authentication entirely; single-machine evaluation only")
		adminEmail = flag.String("admin-email", envOr("LAZARET_ADMIN_EMAIL", ""), "create this admin account on first run if no users exist")
		adminPass  = flag.String("admin-password", envOr("LAZARET_ADMIN_PASSWORD", ""), "password for -admin-email")
		issueToken = flag.String("issue-token", "", "print a new API token with this name and exit")
		tokenRole  = flag.String("issue-token-role", "analyst", "role for -issue-token")
	)
	flag.Parse()

	// Telemetry first, so everything constructed below is already instrumented and
	// start-up itself is visible. Off unless a collector is configured.
	// A misconfigured collector must not stop mail being processed: observability
	// is not allowed to take down the thing it observes. Say so loudly and carry on
	// with no-op providers.
	otelShutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Service: "lazaret-engine",
		Version: buildVersion(),
	})
	if err != nil {
		log.Printf("telemetry: disabled, %v", err)
		otelShutdown = func(context.Context) error { return nil }
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			log.Printf("telemetry: shutting down: %v", err)
		}
	}()

	// -rules is optional now. A directory of local content is still supported and
	// still loaded, but a fresh install gets the Sublime corpus from a rule feed,
	// which is seeded below — so requiring a populated directory here would refuse
	// to start the very deployment this is meant to make work.

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Issuing a credential needs identity and nothing else, so it runs before the
	// corpus is attached and exits. Otherwise minting a token would require knowing
	// the exact data path a DuckLake catalog was created with.
	if *issueToken != "" {
		ist, err := store.OpenIdentityOnly(ctx, *pgConn)
		if err != nil {
			return err
		}
		defer ist.Close()
		token, err := ist.NewAPIToken(ctx, *tenant, *issueToken, store.Role(*tokenRole))
		if err != nil {
			return err
		}
		fmt.Println(token)
		fmt.Fprintln(os.Stderr, "This is shown once. Only a hash is stored.")
		return nil
	}

	st, err := store.Open(ctx, store.Options{
		Postgres: *pgConn,
		DataPath: *dataPath,
		RawPath:  *rawPath,
		// The state volume, which is local and writable even when the corpus and
		// custody live in a blob store. DuckDB spills here rather than failing a
		// query that does not fit in the budget it was given.
		TempPath:    filepath.Join(*stateDir, "duckdb-tmp"),
		S3Endpoint:  *s3Endpoint,
		S3Region:    *s3Region,
		S3AccessKey: *s3Key,
		S3SecretKey: *s3Secret,
		S3UseSSL:    *s3SSL,
	})
	if err != nil {
		return err
	}
	defer st.Close()

	// Validated at startup rather than when Microsoft first refuses a
	// subscription: a malformed callback URL fails by notifications quietly not
	// arriving, which looks like a mailbox that has gone quiet.
	base, err := publicBase(*publicURL)
	if err != nil {
		return err
	}

	// Generated on first start rather than demanded of the operator. See
	// bootstrap.go for the tradeoff this makes and why it is the right default.
	resolvedKey, err := ensureSecretKey(*secretKey, *stateDir)
	if err != nil {
		return err
	}
	if resolvedKey != "" {
		key, err := hex.DecodeString(resolvedKey)
		if err != nil {
			return fmt.Errorf("the credential key must be hex: %w", err)
		}
		box, err := store.NewSecretBox(key)
		if err != nil {
			return err
		}
		st.SetSecretBox(box)
	}

	// The tenant row is created before its configuration is read, so a first run has
	// somewhere to put it.
	if err := st.EnsureTenant(ctx, *tenant, *tenant, nil); err != nil {
		return fmt.Errorf("creating tenant: %w", err)
	}

	// Configuration comes from the database, so it can be changed at runtime, and
	// -org seeds it on a first run rather than overriding what an admin has since
	// set. A file that silently reverts a change made in the UI is worse than no
	// file at all.
	org := &orgconfig.Config{}
	if stored, err := st.OrgConfig(ctx, *tenant); err == nil && len(stored) > 2 {
		if cfg, err := parseOrg(stored); err == nil {
			org = cfg
		}
	}
	if len(org.Domains) == 0 && *orgPath != "" {
		if loaded, err := orgconfig.Load(*orgPath); err == nil {
			org = loaded
			if b, err := json.Marshal(org); err == nil {
				_ = st.EnsureTenant(ctx, *tenant, *tenant, b)
			}
			log.Printf("seeded the organisation configuration from %s", *orgPath)
		} else {
			return err
		}
	}
	if len(org.Domains) == 0 {
		log.Printf("no verified domains configured: message direction will be unknown and " +
			"most rules will report indeterminate. Set them at /v0/org or in the dashboard.")
	}

	// Every named list the corpus references, from whichever of the five sources
	// supplies it, with operator overrides applied last.
	listManager, err := NewListManager(ctx, st, *tenant, org)
	if err != nil {
		return fmt.Errorf("setting up lists: %w", err)
	}
	resolver := mql.ListResolver(listManager)

	mux := mql.NewMux()
	var providers []string

	// Always available: no service, no model, nothing to configure.
	mux.Handle(sensitive.New(), sensitive.Capabilities()...)
	providers = append(providers, "sensitive")

	// The whole point of this service. profile.* is 898 corpus calls and, until now,
	// answerable only from a hand-written file.
	mux.Handle(profile.New(st), profile.Capabilities()...)
	providers = append(providers, "profile")

	// Office document analysis. Local like sensitive: an Office file is a zip or a
	// compound file, so this needs no service and is always available.
	mux.Handle(oletools.New(), oletools.Capabilities()...)
	providers = append(providers, "oletools")

	if *strelkaAddr != "" {
		client, err := strelka.Dial(&strelka.Options{
			Address: *strelkaAddr, Gatekeeper: true,
			DialOptions: []grpc.DialOption{telemetry.GRPCDialOption()},
		})
		if err != nil {
			return err
		}
		defer client.Close()
		mux.Handle(client, strelka.Capabilities()...)
		providers = append(providers, "strelka")
	}
	var renderClient *render.Client
	if *renderAddr != "" {
		rc := render.New(&render.Options{Address: *renderAddr, HTTPClient: telemetry.Client(nil)})
		renderClient = rc
		mux.Handle(rc, render.Capabilities()...)
		providers = append(providers, "render")
		if *linkAnalysis {
			mux.Handle(rc.EnableLinkAnalysis(), render.LinkAnalysisCapability())
			providers = append(providers, "link-analysis")
		}
	}
	var mlClient *ml.Client
	if *mlAddr != "" {
		mlClient = ml.New(&ml.Options{Address: *mlAddr, HTTPClient: telemetry.Client(nil)})
		mux.Handle(mlClient, ml.Capabilities()...)
		providers = append(providers, "ml")
	}

	engineOpts := &rules.Options{Lists: resolver, SkipDisabled: true, Concurrency: *ruleConcurrency}
	if *enableRDAP {
		mux.Handle(rdap.New(&rdap.Options{HTTPClient: telemetry.Client(nil)}), rdap.Capabilities()...)
		providers = append(providers, "rdap")
		reg, err := rdap.ExtendedRegistry()
		if err != nil {
			return err
		}
		engineOpts.Registry = reg
	}

	engine, failures, err := loadRules(*rulesDir, engineOpts)
	if err != nil && *rulesDir != "" {
		log.Printf("local rules in %s could not be loaded (%v); continuing with feeds only", *rulesDir, err)
		engine, failures = emptyEngine(engineOpts)
	} else if err != nil {
		engine, failures = emptyEngine(engineOpts)
	}
	for _, f := range failures {
		log.Printf("skipped %v", f)
	}

	pipeline := &Pipeline{
		store:         st,
		org:           org,
		enricher:      mux,
		lists:         listManager,
		providerNames: providers,
		timeout:       *analysisTimeout,
		ml:            mlClient,
	}
	pipeline.setRules(engine)

	// Overload becomes a queue, and a queue that does not drain becomes an honest
	// refusal rather than a collapse.
	admit := newAdmitter(*maxAnalyses, *analysisQueueWait)

	// Detection content: seed the defaults on a fresh install, then keep every
	// enabled feed up to date in the background.
	feeds := startRuleFeeds(ctx, st, pipeline, *tenant, *stateDir, *rulesDir, engineOpts)

	if err := bootstrapAdmin(ctx, st, *tenant, *adminEmail, *adminPass, *noAuth); err != nil {
		return err
	}

	// The mail connector needs an admin token to read the mailbox list, and on a
	// fresh deployment there is nobody to mint one. Provisioned here, into a file
	// the connector reads, so that bringing the stack up is one command.
	if err := ensureConnectorToken(ctx, st, *tenant, *stateDir); err != nil {
		log.Printf("could not provision the connector token: %v", err)
	}

	// Built here so it can share the engine's function set: a hunt must accept
	// exactly the expressions the rules accept, extensions included.
	hunter := NewHunter(st, listManager)
	hunter.UseRegistry(pipeline.Registry())

	backtester := NewBacktester(st, listManager)
	backtester.UseRegistry(pipeline.Registry())

	// New intelligence about old mail, from the two directions it arrives from.
	//
	// Both file into the same findings table and neither acts on its own. See retro.go
	// for why a feed update must not quarantine three hundred delivered messages.
	retro := NewRetro(st, listManager, pipeline.rules, *tenant, *retroWindow)
	retro.UseRegistry(pipeline.Registry())
	if *retroSweep {
		retro.Arm()
		feeds.OnNewRules(func(ctx context.Context, names []string) {
			if _, err := retro.SweepRules(ctx, names); err != nil {
				log.Printf("retro: sweeping %d new rule(s): %v", len(names), err)
			}
		})
		// The other direction intelligence arrives from. A threat-intel list gaining
		// a domain makes the rules that read it able to catch mail they could not
		// catch when it was delivered.
		listManager.OnChange(func(ctx context.Context, names []string) {
			if _, err := retro.SweepLists(ctx, names); err != nil {
				log.Printf("retro: sweeping after %d list update(s): %v", len(names), err)
			}
		})
	}

	// Links are only worth re-visiting if there is something to visit them with, and
	// only if this deployment already follows links at analysis time: a deployment
	// that deliberately does not reach out to attacker-chosen addresses must not
	// start doing so on a timer.
	if renderClient != nil && *linkAnalysis && *linkWatch {
		watcher := NewLinkWatcher(st, renderClient.EnableLinkAnalysis(), *tenant)
		pipeline.WatchLinks(watcher)
		go watcher.Run(ctx)
		log.Printf("link re-detonation on: links in delivered mail are checked again "+
			"%s after delivery and up to %d times", 30*time.Minute, 4)
	}

	api := &API{
		publicBase:    base,
		store:         st,
		pipeline:      pipeline,
		hunter:        hunter,
		backtest:      backtester,
		retro:         retro,
		feeds:         feeds,
		admit:         admit,
		lists:         listManager,
		defaultTenant: *tenant,
		maxBody:       *maxBody,
		noAuth:        *noAuth,
	}

	// Whatever this deployment has learned from its own analysts, if anything.
	// Absent is the normal state until enough messages have been reviewed.
	api.loadModel(ctx, *tenant)

	// Remote lists on their own schedules, and a rebuild every few minutes so the
	// history-derived ones keep up with what has arrived. Separate cadences because
	// tranco moves weekly and sender_emails moves with every message.
	go listManager.RefreshLoop(ctx, 15*time.Minute)
	go listManager.RebuildLoop(ctx, 5*time.Minute)

	if *noAuth {
		log.Printf("")
		log.Printf("  *** AUTHENTICATION IS DISABLED (-no-auth) ***")
		log.Printf("  Every caller is treated as an admin. Anyone who can reach %s can", *addr)
		log.Printf("  read every message and quarantine mail. Evaluation only.")
		log.Printf("")
	}

	// Expired sessions are already refused by the query that resolves them; this is
	// housekeeping so the table does not grow without bound.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = st.PurgeSessions(ctx)
			}
		}
	}()

	if *compactEvery > 0 {
		// Compaction is the engine's job and the ADR says so: DuckLake inlines small
		// writes and they become Parquet files, and a corpus of millions of tiny files
		// scans badly. Scheduled here rather than left to an operator to remember.
		go compactLoop(ctx, st, *compactEvery)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           telemetry.Middleware("lazaret-engine", api.Routes()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Printf("lazaret-engine listening on %s", *addr)
	log.Printf("  rules: %d loaded from %s", engine.Len(), *rulesDir)
	log.Printf("  enrichment: %v", providers)
	reportCapabilityHealth(ctx, pipeline)
	reportInference(ctx, pipeline)

	// The startup report above is a snapshot taken while the renderer and the model
	// service may still be starting. This keeps watching and says when the picture
	// changes, so the log corrects itself instead of leaving a stale alarm.
	go watchCapabilityHealth(ctx, pipeline)
	log.Printf("  corpus: %s", *dataPath)
	log.Printf("  at most %d messages analysed at once; beyond that they queue for %s and are then refused",
		admit.Limit(), *analysisQueueWait)

	// Naming what is absent, at start-up, next to the flag that would supply it.
	// Otherwise the first anyone learns that most of their rule set cannot run is a
	// coverage page they may never open.
	for _, missing := range []struct {
		set        bool
		what, flag string
	}{
		{*strelkaAddr != "", "file.explode, beta.ocr, beta.scan_qr, beta.parse_exif", "-strelka"},
		{*renderAddr != "", "file.message_screenshot, file.html_screenshot", "-render"},
		{*mlAddr != "", "ml.nlu_classifier, ml.logo_detect and the rest of ml.*", "-ml"},
	} {
		if !missing.set {
			log.Printf("  not configured: %s — set %s", missing.what, missing.flag)
		}
	}

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func compactLoop(ctx context.Context, st *store.Store, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := st.Compact(ctx); err != nil {
				log.Printf("compaction: %v", err)
			}
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envFileOr is envOr that also accepts the value in a file, named by KEY_FILE.
//
// The convention Docker and Kubernetes already use for secrets, and the thing
// that lets a credential reach this process without ever being an environment
// variable — env is readable from /proc, inherited by children and printed by
// every "docker inspect". It is also what makes the blob store self-configuring:
// the bootstrap writes the key it created to a shared volume and this reads it,
// so nobody has to run a command, copy its output into .env and start again.
//
// KEY wins over KEY_FILE when both are set, so an operator supplying their own
// credential is never overridden by a generated one.
func envFileOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if path := os.Getenv(key + "_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			// Fatal rather than falling through: a deployment that asked for a
			// credential from a file and silently got none instead fails later,
			// somewhere less obvious, as a permissions error from the blob store.
			log.Fatalf("lazaret-engine: reading %s from %s: %v", key, path, err)
		}
		return strings.TrimSpace(string(b))
	}
	return def
}

// bootstrapAdmin creates the first account.
//
// A deployment with no users and no way to make one is unusable, and the usual
// answer — a default password — is how products ship with admin/admin. So: an account
// is created only when explicitly asked for and only when none exists, and a
// deployment with neither that nor -no-auth refuses to start rather than listening
// with no way in.
func bootstrapAdmin(ctx context.Context, st *store.Store, tenant, email, password string, noAuth bool) error {
	n, err := st.CountUsers(ctx, tenant)
	if err != nil {
		return fmt.Errorf("counting users: %w", err)
	}
	if n > 0 {
		if email != "" {
			log.Printf("-admin-email ignored: %d account(s) already exist", n)
		}
		return nil
	}

	if email == "" {
		if noAuth {
			return nil
		}
		return errors.New("no accounts exist and none was requested: pass -admin-email and " +
			"-admin-password to create the first one, or -no-auth for an evaluation")
	}
	if password == "" {
		return errors.New("-admin-email needs -admin-password")
	}

	if _, err := st.CreateUser(ctx, store.User{
		TenantID: tenant, Email: email, Name: email, Role: store.RoleAdmin,
	}, password); err != nil {
		return fmt.Errorf("creating the first admin: %w", err)
	}
	log.Printf("created the first admin account: %s", email)
	return nil
}

// buildVersion is the binary's own version, read from the build info the toolchain
// embeds. Reported as service.version so a trace can be tied to what was deployed.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return info.Main.Version
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev + dirty
}

// emptyEngine is the starting rule set for a deployment whose content has not been
// fetched yet. It answers nothing, and the feed syncer replaces it within seconds
// of the first clone finishing.
func emptyEngine(opts *rules.Options) (*rules.Engine, []*rules.LoadError) {
	return rules.New(nil, opts)
}

// startRuleFeeds seeds the defaults on a fresh install, brings the content up to
// date, and keeps it that way.
//
// Seeding here rather than in a migration because it needs a tenant to exist, and
// because "a new deployment detects something out of the box" is a behaviour worth
// stating in the start-up log rather than hiding in schema.
func startRuleFeeds(ctx context.Context, st *store.Store, p *Pipeline, tenant, stateDir, localDir string, opts *rules.Options) *FeedSyncer {
	seeded, err := st.SeedRuleFeeds(ctx, tenant)
	if err != nil {
		log.Printf("rule feeds: seeding defaults: %v", err)
	} else if seeded {
		var names []string
		for _, f := range store.SeededFeeds() {
			names = append(names, strconv.Quote(f.Name))
		}
		log.Printf("  rule feeds: seeded %s for a fresh install", strings.Join(names, " and "))
	}

	syncer := NewFeedSyncer(st, p, tenant, stateDir, localDir, opts)

	// The first pass runs in the background: cloning the corpus takes a little
	// while, and an engine that refuses connections until it finishes looks hung.
	// Until it lands the engine answers with whatever local content there is.
	go syncer.Run(ctx)
	return syncer
}

// envInt reads an integer from the environment, falling back to def.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		log.Printf("%s=%q is not a number; using %d", key, v, def)
	}
	return def
}

// envDuration reads a duration from the environment, falling back to def.
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("%s=%q is not a duration; using %s", key, v, def)
	}
	return def
}
