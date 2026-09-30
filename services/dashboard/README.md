# lazaret-dashboard (module 7)

Triage, hunt, rules and insights. Replaces Sublime's `dashboard` container.

## Vue, and why it didn't start that way

A Vue 3 single-page app in TypeScript, built with Vite, embedded into the Go binary with
`go:embed`. The Go side serves the bundle, holds the session, proxies to the engine, and
does nothing else.

The first version was `html/template` with about a hundred lines of vanilla JavaScript.
The argument then was that npm in an otherwise Go repository means a second toolchain, a
build step, a lockfile with several hundred transitive dependencies, and by some distance
the largest attack surface in the product. Against all that it bought a nicer interaction
model across four views.

Two things changed. It stopped being four views, since there are twenty-odd now including
an MQL editor with completion, live type-checking and schema-aware hints, which isn't
something you build with `<textarea>` and good intentions. And the templates were
unpleasant enough to work in that they were quietly shaping what got built, which is the
worse problem of the two.

The original argument is still right about the cost. We pay it deliberately, and the
dependency list is short on purpose: Vue, Vue Router, TanStack Query, CodeMirror, two
fonts. No component library, no CSS framework, no state management library.

## It talks to the engine's public API and nothing else

No database handle, no shared Go types beyond JSON. That's a deliberate constraint rather
than an accident of layering. It keeps the API exercised by a real consumer instead of only
by its own tests, and it means anything the dashboard can do, a script can do too.

It also means the dashboard needs no credentials of its own and the engine needs no CORS
configuration, since every call is proxied through this service rather than made from the
browser. The TypeScript types come from the Go wire structs via `tygo`, so the two can't
drift without the build noticing.

The proxy is 48 explicit handlers rather than a path allowlist. Both
`/v0/mailboxes/{id}/remediations` and `/v0/mailboxes/secrets` exist, the second returns
mailbox passwords, and any pattern broad enough to be convenient eventually matches it.

## Views

| Path | What it is |
|---|---|
| `/triage` | Messages, verdicts, what fired, what has already been done |
| `/overview` | Volume, verdict mix, and what the deployment cannot currently answer |
| `/messages/:id` | The Message Data Model, the audit trail, and the disposition form |
| `/search` | Structured search over stored mail |
| `/hunt` | MQL over stored mail, with completion and live type-checking |
| `/analyzer` | Paste an EML, get a verdict, change nothing |
| `/detections` | What's loaded, and what each rule needs that this deployment may not have |
| `/detections/effectiveness` | Which rules fire, which never have, which only false-positive |
| `/detections/coverage` | Rules that can't run here, grouped by the capability they want |
| `/settings/*` | Org domains, mailboxes, actions, Microsoft 365, history scans, feeds, lists, learning, users |

### Two things the UI is opinionated about

**Coverage is a page, not a footnote.** A report listing detections without mentioning
that nine hundred rule evaluations were blocked on a model nobody deployed makes a partial
system look complete. It's the honest counterpart to the numbers on the overview.

**The disposition form requires an actor.** The engine refuses an action without one and so
does this, so an analyst sees why on the page rather than getting a bare 400 from an API
they didn't know they were calling. The audit trail has no edit path.

## Rendering hostile content

Every string on the triage page was written by someone hostile, since a subject line is
attacker-controlled by definition. So:

- Vue escapes interpolated text, and a test feeds a real payload through rather than
  trusting that it does. `v-html` appears nowhere.
- A strict CSP: `default-src 'none'; script-src 'self'; style-src 'self' 'nonce-...'`, with
  a fresh nonce per request. No inline handlers, no remote scripts, and no remote fonts or
  images, because the fonts are bundled. CodeMirror gets handed the same nonce
  (`EditorView.cspNonce`) since it injects its own stylesheet.
- Redirects after login go through an origin check. A `?next=` that a naive
  `startsWith("/")` accepts includes `//evil.example`, which browsers read as a host.

`-read-only` hides the action controls **and refuses the POST**. Hiding a button isn't
access control, and `TestReadOnlyRefusesActions` checks the difference.

## Authentication

Local passwords and OpenID Connect, and a deployment can have both at once. That
combination is the point rather than indecision. An organisation running SSO still wants
one local break-glass account, because the day the identity provider breaks is exactly the
day someone needs to get into the security console.

**The engine owns identity.** It authenticates people via sessions and services via API
tokens, and enforces roles on every endpoint. The dashboard does the browser half, meaning
a form or an OIDC redirect, and holds the resulting session in a cookie. That ordering
matters, because a login page in front of an unauthenticated API protects the page rather
than the data, and this API can quarantine mail and read every message.

The caller's own session travels to the engine on every request, so the engine sees the
actual person. The dashboard holds one privileged credential and uses it for exactly one
thing: turning verified OIDC claims into a session, since at that moment there's no caller
yet.

### Roles

| Role | Can |
|---|---|
| `viewer` | read triage, messages, insights, rules |
| `analyst` | also act: quarantine, release, set triage state, hunt, analyze |
| `admin` | also manage accounts and API tokens |

A first-time SSO user gets `viewer`. An identity provider vouching that someone works here
isn't the same as deciding they may quarantine mail.

### Getting started

```sh
# The engine creates the first account, and refuses to start with neither this nor
# -no-auth: a system that is insecure until configured ships insecure.
lazaret-engine ... -admin-email you@example.com -admin-password '...'

# SSO additionally needs an admin token for the claims-to-session exchange.
lazaret-engine ... -issue-token dashboard -issue-token-role admin

lazaret-dashboard -engine http://localhost:8700 -service-token lzt_... \
  -oidc-issuer https://login.example.com \
  -oidc-client-id ... -oidc-client-secret ... \
  -oidc-redirect-url https://lazaret.example.com/auth/callback
```

### What the sign-in code is careful about

- **CSRF.** Every state-changing request carries a synchroniser token bound to the
  session, checked in constant time. `SameSite=Lax` is set as well, but that's a browser
  behaviour rather than a server-enforced invariant, and a same-site subdomain can still
  post.
- **Session cookies are `HttpOnly`**, so an XSS can't read one, and `Secure` unless
  `-insecure-cookies` is passed, which logs a warning.
- **Sessions are server-side**, so signing out or disabling an account ends them
  immediately rather than whenever a token would have expired.
- **OIDC uses `state`, `nonce` and PKCE**, and refuses an unverified `email` claim. Several
  providers let a user set any address until it's verified, and an account here is matched
  partly on it.
- **`next=` is local-path only.** Otherwise the login page becomes an open redirect, which
  makes a good phishing lure precisely because it points at the security console.
- **An unrecognised role denies.** A typo in a route's requirement mustn't grant access to
  everyone.
- **Passwords are argon2id** at the OWASP baseline, with a dummy verification when no
  account exists, so response time doesn't reveal who has one.

Still missing, and worth naming: no rate limiting on sign-in, no multi-factor, and no SCIM
provisioning. Put this behind a reverse proxy that handles the first two.
