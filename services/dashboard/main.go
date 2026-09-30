// SPDX-License-Identifier: AGPL-3.0-only

// Command lazaret-dashboard is the web UI — module 7.
//
// Triage, hunt, rules and insights, served as ordinary HTML over the engine's JSON API.
//
// # Why this is Go and not a JavaScript application
//
// The plan said "not a Go module", assuming a single-page app. It is worth saying why
// that changed, because the reasoning is the same one behind every other choice here.
//
// A React or Svelte dashboard means npm in an otherwise Go repository: a second
// toolchain, a build step before anyone can run the thing, a lockfile with several
// hundred transitive dependencies, and a supply chain that is by some distance the
// largest attack surface in a security product. Against that, what it buys for these
// four views is a slightly nicer interaction model.
//
// So: html/template, embedded, no build step, no npm, one static binary. The JavaScript
// that exists is a few dozen lines of vanilla fetch for the things that genuinely need
// to be asynchronous — polling a hunt job, validating a rule as you type. Anyone can
// read all of it.
//
// # It talks to the engine's public API and nothing else
//
// No database connection, no shared types beyond JSON. That is a deliberate constraint
// rather than an accident of layering: it means the API is exercised by a real consumer
// rather than only by tests, and anything the dashboard can do is something a script
// can do too.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"

	"github.com/lazaretemail/lazaret/telemetry"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"time"
)

// The compiled console.
//
// `all:` so that files the front-end build emits with a leading dot are embedded
// too; the default pattern silently skips them, which turns into a 404 for an asset
// that plainly exists on disk.
//
//go:embed all:web/dist
var consoleFS embed.FS

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "lazaret-dashboard: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", envOr("LAZARET_DASHBOARD_ADDR", ":8740"), "listen address")
	engineAddr := flag.String("engine", envOr("LAZARET_ENGINE", "http://localhost:8700"), "lazaret-engine base URL")
	tenant := flag.String("tenant", envOr("LAZARET_TENANT", "default"), "tenant id")
	readOnly := flag.Bool("read-only", false, "refuse every state-changing request")
	serviceToken := flag.String("service-token", envOr("LAZARET_SERVICE_TOKEN", ""), "engine admin API token; needed only for SSO")
	insecureCookies := flag.Bool("insecure-cookies", false, "do not mark cookies Secure; local HTTP development only")

	oidcIssuer := flag.String("oidc-issuer", envOr("LAZARET_OIDC_ISSUER", ""), "OpenID Connect issuer URL")
	oidcClient := flag.String("oidc-client-id", envOr("LAZARET_OIDC_CLIENT_ID", ""), "OIDC client id")
	oidcSecret := flag.String("oidc-client-secret", envOr("LAZARET_OIDC_CLIENT_SECRET", ""), "OIDC client secret")
	oidcRedirect := flag.String("oidc-redirect-url", envOr("LAZARET_OIDC_REDIRECT_URL", ""), "public URL of /auth/callback")
	oidcRole := flag.String("oidc-default-role", envOr("LAZARET_OIDC_DEFAULT_ROLE", "viewer"), "role for a first-time SSO user")
	flag.Parse()

	// A misconfigured collector must not stop mail being processed: observability
	// is not allowed to take down the thing it observes. Say so loudly and carry on
	// with no-op providers.
	otelShutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Service: "lazaret-dashboard",
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

	// The engine client is instrumented, so a slow console page shows which engine
	// call it was waiting on rather than just being slow.
	engine := &EngineClient{Base: *engineAddr, Tenant: *tenant,
		HTTP: telemetry.Client(&http.Client{Timeout: 3 * time.Minute})}

	auth := &Auth{
		Engine:       engine,
		ServiceToken: *serviceToken,
		Secure:       !*insecureCookies,
		DefaultRole:  *oidcRole,
	}
	if *insecureCookies {
		warnInsecure()
	}

	if *oidcIssuer != "" {
		if *oidcClient == "" || *oidcRedirect == "" {
			return errors.New("-oidc-issuer needs -oidc-client-id and -oidc-redirect-url")
		}
		if *serviceToken == "" {
			// Checked at start-up rather than discovered at the end of someone's first
			// sign-in: without it the OIDC dance completes and then cannot create a
			// session, which looks like a broken identity provider.
			return errors.New("-service-token is required for SSO: the engine needs an admin " +
				"credential to turn verified claims into a session (lazaret-engine -issue-token)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := auth.ConfigureOIDC(ctx, *oidcIssuer, *oidcClient, *oidcSecret, *oidcRedirect, nil); err != nil {
			return err
		}
		log.Printf("single sign-on: %s", *oidcIssuer)
	}

	app := &App{engine: engine, auth: auth, readOnly: *readOnly}

	dist, err := fs.Sub(consoleFS, "web/dist")
	if err != nil {
		return err
	}
	handler, err := app.Routes(dist)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           telemetry.Middleware("lazaret-dashboard", handler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      5 * time.Minute,
	}

	log.Printf("lazaret-dashboard on %s, engine %s, tenant %s", *addr, *engineAddr, *tenant)
	if *readOnly {
		log.Printf("  read-only: every state-changing request is refused")
	}
	if !auth.SSOEnabled() {
		log.Printf("  sign-in: local password only")
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// buildVersion reports the revision this binary was built from, for service.version.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return s.Value[:12]
		}
	}
	return info.Main.Version
}
