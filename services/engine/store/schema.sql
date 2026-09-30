-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Postgres holds relational state and the DuckLake catalog. It does not hold the message
-- corpus: see docs/ADR-001-storage.md.
--
-- The split, in one sentence: anything small, mutable and asked about by key lives here;
-- anything wide, immutable and scanned lives in DuckLake.

CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Verified message-source domains, VIPs and display names. type.inbound is defined
    -- relative to these, and 1,293 corpus rules are gated on it, so a tenant without
    -- this configured cannot be evaluated correctly rather than merely incompletely.
    org_config  JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS rules (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id          TEXT NOT NULL,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT,
    source      TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- The action log. This is the part of the platform the project is named for: what was
-- quarantined, what was released, and who decided. Append-only by convention and by the
-- absence of an UPDATE path — an audit trail that can be edited is not one.
CREATE TABLE IF NOT EXISTS actions (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id  TEXT NOT NULL,
    action      TEXT NOT NULL,
    reason      TEXT,
    actor       TEXT NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS actions_tenant_at ON actions (tenant_id, at DESC);
CREATE INDEX IF NOT EXISTS actions_message ON actions (tenant_id, message_id);

-- The materialised current profile, for the delivery path.
--
-- This is the "now" half of the two-store design. It answers profile.* in one indexed
-- lookup during delivery, and it is rebuildable in full from the sender_events table in
-- DuckLake, which is the source of truth. It deliberately cannot answer "as of March":
-- that question goes to the event log, because a mutable row has no history and a
-- backtest reading one would silently see the future.
CREATE TABLE IF NOT EXISTS sender_profiles (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,   -- email | domain | reply_to
    key             TEXT NOT NULL,
    messages        BIGINT NOT NULL DEFAULT 0,
    first_contact   TIMESTAMPTZ,
    last_contact    TIMESTAMPTZ,
    last_inbound    TIMESTAMPTZ,
    last_outbound   TIMESTAMPTZ,
    solicited       BOOLEAN NOT NULL DEFAULT FALSE,
    any_benign      BOOLEAN NOT NULL DEFAULT FALSE,
    any_malicious   BOOLEAN NOT NULL DEFAULT FALSE,
    any_false_pos   BOOLEAN NOT NULL DEFAULT FALSE,
    all_auth_failed BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (tenant_id, kind, key)
);

-- Hunt jobs. Small, mutable, polled by id — relational state, not corpus.
CREATE TABLE IF NOT EXISTS hunt_jobs (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    state       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    scanned     BIGINT NOT NULL DEFAULT 0,
    matched     BIGINT NOT NULL DEFAULT 0,
    error       TEXT,
    results     JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS hunt_jobs_tenant ON hunt_jobs (tenant_id, created_at DESC);

-- Identity.
--
-- The engine owns this because the engine owns state. It authenticates two kinds of
-- caller: people, who get sessions from a browser flow, and services, which get API
-- tokens. Both resolve to a role, and the API checks the role rather than the caller.
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email         TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',

    -- Local password, argon2id. Null for an SSO-only account, which is the point of
    -- allowing both: an organisation can run SSO and still keep one break-glass local
    -- account for when the identity provider is the thing that is down.
    password_hash TEXT,

    -- External identity, as issuer + subject. Matched on before email, because an
    -- email address can be reassigned to a different person and a subject cannot.
    oidc_issuer   TEXT,
    oidc_subject  TEXT,

    -- viewer | analyst | admin
    role          TEXT NOT NULL DEFAULT 'viewer',
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login    TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users (tenant_id, lower(email));
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc ON users (oidc_issuer, oidc_subject)
    WHERE oidc_issuer IS NOT NULL;

-- Sessions. Server-side rather than a signed cookie, so that disabling an account or
-- signing out actually ends the session rather than waiting for a token to expire.
CREATE TABLE IF NOT EXISTS sessions (
    -- The SHA-256 of the token, never the token. A stolen database should not yield
    -- working sessions.
    token_hash  BYTEA PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    user_agent  TEXT,
    ip          TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);

-- Service credentials. The dashboard, the ingest connectors, anything automated.
CREATE TABLE IF NOT EXISTS api_tokens (
    token_hash  BYTEA PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'analyst',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used   TIMESTAMPTZ,
    disabled    BOOLEAN NOT NULL DEFAULT FALSE
);

-- Triage state, which is a property of the investigation rather than of the message.
--
-- Separate from the corpus for exactly that reason: the corpus is append-only and
-- immutable, and "has an analyst looked at this yet" changes. Keeping it here means
-- the message record never has to be rewritten.
CREATE TABLE IF NOT EXISTS triage (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id  TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'unreviewed',
    assignee    TEXT,
    reviewed_by TEXT,
    reviewed_at TIMESTAMPTZ,
    note        TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, message_id)
);
CREATE INDEX IF NOT EXISTS triage_state ON triage (tenant_id, state, updated_at DESC);

-- What we learned about mail that had already been delivered.
--
-- Attribution lags delivery. A feed adds a domain at two in the afternoon and the
-- message carrying it arrived at nine that morning; a link that served a 404 at
-- delivery serves a credential form an hour later, which is a standard way to get past
-- anything that looks once. Neither is visible to a pipeline that only ever judges mail
-- on the way in.
--
-- A finding is this engine saying "what I concluded about that message was reached
-- without something I now know". It is deliberately not a verdict and never an action:
-- a retrospective sweep does not remediate, for the same reason a history scan does not
-- — a message delivered two months ago is not a delivery decision today, and a feed
-- update that quarantined three hundred old messages would be a bad afternoon. It is
-- surfaced, and a person decides.
CREATE TABLE IF NOT EXISTS retro_findings (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id  TEXT NOT NULL,

    -- rule | link. A rule finding is new or changed detection content matching mail
    -- already delivered; a link finding is a URL that changed after the message was
    -- judged on it.
    kind        TEXT NOT NULL,

    -- source names what produced it: a rule name, or the URL that changed.
    source      TEXT NOT NULL,
    detail      TEXT,

    -- state is what a person has done about it: new | dismissed | actioned.
    state       TEXT NOT NULL DEFAULT 'new',
    found_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by TEXT,
    reviewed_at TIMESTAMPTZ,

    -- One finding per message per source. A sweep that runs nightly must not file the
    -- same discovery every night, and a link checked three times must not file three.
    UNIQUE (tenant_id, message_id, kind, source)
);
CREATE INDEX IF NOT EXISTS retro_findings_open
    ON retro_findings (tenant_id, state, found_at DESC);

-- Links to look at again after the message has been delivered.
--
-- A URL is not a constant. It is a thing an attacker controls, and the cheapest evasion
-- against a scanner that looks once is to serve something harmless until the mail has
-- landed. Re-visiting on a schedule is what turns that from a blind spot into a
-- detection.
--
-- due_at rather than a fixed interval, so the schedule can widen as a link ages: the
-- interesting window is the first day, and a link nobody has weaponised by then is
-- unlikely to be.
CREATE TABLE IF NOT EXISTS link_watch (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    message_id  TEXT NOT NULL,

    -- digest is what the link looked like when the message was judged, so a later
    -- visit can tell "changed" from "the same as it ever was" without keeping the page.
    digest      TEXT NOT NULL,

    attempts    INT NOT NULL DEFAULT 0,
    due_at      TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, url, message_id)
);
CREATE INDEX IF NOT EXISTS link_watch_due ON link_watch (tenant_id, due_at);

-- Named list configuration.
--
-- Every list a rule can reference is one row here, whatever supplies its contents. The
-- point of the table is not storage — most lists are supplied by something else — but
-- *configuration*: whether a list is enabled, where it comes from, and what an
-- operator has added to or removed from it.
CREATE TABLE IF NOT EXISTS lists (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,

    -- embedded | fetch | feed | org | history | manual
    source      TEXT NOT NULL DEFAULT 'manual',

    -- Where a fetch or feed list comes from. Null for the others.
    url         TEXT,
    auth_header TEXT,
    format      TEXT NOT NULL DEFAULT 'lines',   -- lines | csv1 | csv2 | json

    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT NOT NULL DEFAULT '',

    refresh_every INTERVAL NOT NULL DEFAULT INTERVAL '24 hours',
    last_refresh  TIMESTAMPTZ,
    last_error    TEXT,
    entry_count   BIGINT NOT NULL DEFAULT 0,

    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

-- A fetched or feed list's contents, cached so a restart does not mean a cold start
-- and an upstream outage does not silently empty a list.
CREATE TABLE IF NOT EXISTS list_cache (
    tenant_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, name, value)
);
CREATE INDEX IF NOT EXISTS list_cache_name ON list_cache (tenant_id, name);

-- What an operator has added or removed.
--
-- Kept apart from the cached contents so a refresh never discards them: an exclusion
-- someone added because a list wrongly contains their own domain must survive the next
-- download, and losing it would re-break the thing they fixed.
CREATE TABLE IF NOT EXISTS list_overrides (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    value      TEXT NOT NULL,
    kind       TEXT NOT NULL,          -- include | exclude
    note       TEXT NOT NULL DEFAULT '',
    added_by   TEXT NOT NULL DEFAULT '',
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Case-insensitive uniqueness, as an index rather than a primary key: Postgres does
-- not allow an expression in a PRIMARY KEY. Case-insensitive because a domain is, and
-- excluding "Example.com" must also exclude "example.com".
CREATE UNIQUE INDEX IF NOT EXISTS list_overrides_key
    ON list_overrides (tenant_id, name, lower(value), kind);

-- Mailboxes to collect from.
--
-- Configuration rather than flags, because adding a mailbox is a routine operational
-- act and restarting a connector to do it is not. Secrets are stored here; see the
-- note in store/mailbox.go about what that does and does not protect.
CREATE TABLE IF NOT EXISTS mailboxes (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,            -- imap | graph
    address     TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,

    -- IMAP
    host        TEXT,
    username    TEXT,
    secret_enc  BYTEA,
    tls_mode    TEXT NOT NULL DEFAULT 'tls',
    folder      TEXT NOT NULL DEFAULT 'INBOX',
    remediate   BOOLEAN NOT NULL DEFAULT false,

    -- Graph: the tenant/app registration lives in config; this is which mailbox.
    graph_user  TEXT,

    last_seen   TIMESTAMPTZ,
    last_error  TEXT,
    messages    BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mailboxes_tenant ON mailboxes (tenant_id, enabled);

-- Work for a connector: something to do to a mailbox.
--
-- Quarantine takes a message out of the mailbox entirely rather than moving it to a
-- folder, so the act and the decision happen in different processes — an analyst
-- releases a message in the dashboard, and the mailbox is reachable only from the
-- connector. This table is what carries the intent across that gap, and what makes it
-- visible afterwards whether it was carried out.
CREATE TABLE IF NOT EXISTS remediations (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    op         TEXT NOT NULL,                       -- remove | restore
    state      TEXT NOT NULL DEFAULT 'pending',     -- pending | done | failed
    attempts   INT  NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    done_at    TIMESTAMPTZ
);

-- One outstanding job per (message, mailbox, op). A second click on Release while the
-- first is still in flight should not queue a second restore.
CREATE UNIQUE INDEX IF NOT EXISTS remediations_pending
    ON remediations (tenant_id, message_id, mailbox_id, op) WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS remediations_queue
    ON remediations (tenant_id, mailbox_id, state, id);

-- Why a flagged message was released.
--
-- Separate from the action log, which is append-only history: this is the current
-- judgement about one message and it can be revised. The distinction it carries is
-- the one that matters for tuning — "false_positive" means the rule was wrong,
-- "accepted_risk" means the rule was right and someone wanted the message anyway.
-- Counting the second against a rule teaches operators to tune away detections that
-- work.
CREATE TABLE IF NOT EXISTS dispositions (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id  TEXT NOT NULL,
    disposition TEXT NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, message_id)
);

-- Which mailbox a message arrived in.
--
-- Recorded so that removing or restoring it can be aimed at one connector instead of
-- queued against every mailbox in the tenant. Absent for mail seen in transit — the
-- inline Rspamd path never had a mailbox — and absent for anything ingested before a
-- connector was managed by the engine, so remediation must still fall back to a
-- fan-out when there is no row here.
CREATE TABLE IF NOT EXISTS message_origin (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, message_id, mailbox_id)
);

-- Added after the lists table shipped, so ALTER rather than a column in CREATE.
--
-- filter narrows a downloaded feed whose published export is broader than the list
-- the rules name; fallback_to points at another list for one whose upstream no longer
-- exists. Both are per-tenant decisions rather than ours to make in code.
ALTER TABLE lists ADD COLUMN IF NOT EXISTS filter TEXT;
ALTER TABLE lists ADD COLUMN IF NOT EXISTS fallback_to TEXT;

-- The model learned from analyst reviews.
--
-- Postgres rather than the corpus: a few kilobytes of weights, rewritten whole on
-- each training run and read on every ingest, which is the opposite of what a
-- columnar store is for.
--
-- Versioned rather than overwritten, so a model that turns out worse can be compared
-- with the one before it, and so an audit can answer what the system was using on the
-- day it made a particular decision.
CREATE TABLE IF NOT EXISTS learned_models (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    version    INT  NOT NULL,
    weights    JSONB NOT NULL,
    trained_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version)
);

-- Screenshots of message bodies, rendered server-side.
--
-- A cache, not a record. The PNG is derived from bytes already held and can be thrown
-- away and made again, which is exactly why it does not live in custody: custody holds
-- the only copy of a quarantined message and nothing regenerable belongs beside it,
-- where a purge or a restore could mistake one for the other.
--
-- Postgres rather than object storage because these are small, read immediately after
-- they are written, and bound in number by how many messages an analyst opens. If that
-- stops being true the table is a cache and can be dropped.
--
-- Keyed by a digest of the rendered HTML as well as the message, so that a message
-- re-parsed by a newer engine does not serve the previous picture of itself.
CREATE TABLE IF NOT EXISTS screenshots (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL,
    digest     TEXT NOT NULL,
    png        BYTEA NOT NULL,
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, message_id)
);

-- Retrospective scans of a mailbox's existing mail.
--
-- A backfill is a bounded walk of what is already in a mailbox, evaluated as if it
-- had just arrived, for two purposes an operator has on day one: finding what was
-- delivered before the platform existed, and giving the sender history and the
-- learned model something to be built from. A deployment with no history answers
-- "have we heard from this sender before" with "no" for every sender alive.
--
-- The state lives here rather than in the connector because the connector is
-- stateless and replaceable, and because a scan of ninety days of mail outlives any
-- one process. A connector claims a job, reports progress, and can die and be
-- replaced without losing its place.
--
-- Chronological order is not a detail. Sender profiles answer from events strictly
-- before the message being evaluated, so a message is judged against whatever was
-- stored when it was processed. Walking oldest-first rebuilds the history in the
-- order it actually happened; walking newest-first judges January's mail against
-- March's knowledge, and every early message looks like a first contact. The cursor
-- below is therefore a timestamp, and it only moves forward.
CREATE TABLE IF NOT EXISTS backfills (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    mailbox_id  TEXT NOT NULL,

    -- The window, inclusive of since and exclusive of until.
    since       TIMESTAMPTZ NOT NULL,
    until       TIMESTAMPTZ NOT NULL,

    -- pending | running | paused | done | failed | cancelled
    state       TEXT NOT NULL DEFAULT 'pending',

    -- cursor is how far the walk has got, in the mailbox's own time. Resuming
    -- starts here rather than at the beginning.
    cursor      TIMESTAMPTZ,

    -- What the scan has seen. found is how many messages matched the window;
    -- the rest are outcomes, and flagged is the number an operator has to look at.
    examined    BIGINT NOT NULL DEFAULT 0,
    ingested    BIGINT NOT NULL DEFAULT 0,
    duplicates  BIGINT NOT NULL DEFAULT 0,
    flagged     BIGINT NOT NULL DEFAULT 0,
    failures    BIGINT NOT NULL DEFAULT 0,

    -- Whether the original bytes are kept. Ninety days of mail is a great deal of
    -- storage and custody exists to make quarantine reversible — which a
    -- retrospective scan does not do — so it is opt-in per job.
    keep_raw    BOOLEAN NOT NULL DEFAULT false,

    -- last_error survives every batch that does not replace it, and now survives
    -- the scan finishing too, so the reason a message failed outlives the scan
    -- that hit it. That is deliberate — it is the only diagnostic a transient
    -- failure leaves — but it means the text alone says nothing about *when*, and
    -- a scan that has since ingested hundreds of messages was reading on the
    -- history page as broken. last_error_at is what tells the two apart.
    last_error  TEXT,
    last_error_at TIMESTAMPTZ,
    claimed_by  TEXT,
    claimed_at  TIMESTAMPTZ,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

-- One active scan per mailbox. Two walking the same mailbox would duplicate every
-- message and race each other's cursor.
CREATE UNIQUE INDEX IF NOT EXISTS backfills_one_active
    ON backfills (tenant_id, mailbox_id)
    WHERE state IN ('pending', 'running', 'paused');

-- Which retrospective scan found a message, when one did.
--
-- Provenance, and it changes how a verdict should be read. "This was flagged as it
-- arrived" and "this was found weeks later by looking back" are different claims:
-- the first is the platform working, the second is the platform telling you it was
-- not there at the time. Reporting that conflates them overstates effectiveness on
-- the day a deployment is installed, which is exactly the day someone is deciding
-- whether to trust it.
ALTER TABLE backfills ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ;

ALTER TABLE message_origin ADD COLUMN IF NOT EXISTS backfill_id TEXT;

-- The Microsoft 365 application registration.
--
-- One per deployment rather than one per mailbox, because that is what it is: an
-- app registration in a directory, with permission over the mailboxes in it. Every
-- Graph mailbox uses the same one, which is why it could not live on the mailbox
-- row and why it was the last thing still configured by a command-line flag.
--
-- The client secret is encrypted with the same key as mailbox credentials and is
-- never read back out to a browser — only to a connector authenticating with a
-- service token, exactly like mailbox credentials.
CREATE TABLE IF NOT EXISTS graph_app (
    tenant_id     TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    -- The Microsoft directory (tenant) id and the application (client) id. Both
    -- are identifiers, not secrets: they appear in every token request and in the
    -- consent URL an administrator clicks.
    directory_id  TEXT NOT NULL,
    client_id     TEXT NOT NULL,

    -- Encrypted at rest. Null when the registration uses an existing secret that
    -- has not been re-entered.
    client_secret BYTEA,

    -- The secret Graph echoes back in every notification, so a notification that
    -- did not come from Microsoft can be told apart from one that did. Generated
    -- rather than typed: it has no meaning outside this pairing.
    client_state  BYTEA,

    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by    TEXT
);

-- Configured actions: a named, configured thing an administrator created.
--
-- A type is what the platform can do; an instance is a decision about how. "Move to
-- Spam" and "Move to Promotions" are the same type with different folders, and a
-- rule is attached to the instance rather than to the type — so a deployment
-- decides once what trashing means and then applies it to a thousand rules.
-- Named action_configs, not actions: `actions` is already the audit log — what was
-- done to one message — and these are what this deployment is set up to do. Two
-- quite different things with one obvious name between them, and CREATE TABLE IF
-- NOT EXISTS would have silently kept the audit log and left every column here
-- missing, which fails at runtime rather than at deploy.
CREATE TABLE IF NOT EXISTS action_configs (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    label      TEXT NOT NULL,
    type       TEXT NOT NULL,
    config     JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- A deployment-wide off switch. Disabling an instance stops every rule using
    -- it without anyone having to remember which rules those were.
    enabled    BOOLEAN NOT NULL DEFAULT true,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS action_configs_label_unique
    ON action_configs (tenant_id, lower(label));

-- Which actions a rule takes when it fires.
--
-- Empty for every rule until an administrator says otherwise, and that is the
-- important part: a fresh deployment detects and reports and changes nothing. This
-- table is how automated mailbox mutation gets turned on, one rule at a time, by
-- somebody who meant to.
--
-- Keyed by rule id rather than by name. Rules are loaded from YAML and their names
-- change with wording; the id is what the corpus uses to refer to one, and an
-- action attached to a renamed rule should follow the rule.
CREATE TABLE IF NOT EXISTS rule_actions (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id   TEXT NOT NULL,
    action_id TEXT NOT NULL REFERENCES action_configs(id) ON DELETE CASCADE,
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by  TEXT,
    PRIMARY KEY (tenant_id, rule_id, action_id)
);

CREATE INDEX IF NOT EXISTS rule_actions_by_action ON rule_actions (action_id);

-- The op column was 'remove' or 'restore'. It now carries any action kind, so a
-- deployment upgrading in place keeps its queue: 'remove' still means quarantine.
-- Nothing is rewritten, because a queued remediation is work somebody is waiting on.
COMMENT ON COLUMN remediations.op IS
    'remove | restore | trash | spam | flag | mark_read — the action to carry out';

-- Actions carry their settings with them.
--
-- A "move" needs to know where to, and the folder belongs to the configured action.
-- Copied onto the queued row rather than looked up at execution time, so that
-- editing an action does not change what an already-queued one will do — a queue is
-- a list of decisions already taken.
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}'::jsonb;

-- The notification URL is derived, not stored.
--
-- It was a field on the registration form, which made an administrator responsible
-- for a path this code already knows and gave them a way to get it subtly wrong —
-- a trailing slash, http where the proxy wants https, a path left behind when the
-- endpoint moved. It is now built from LAZARET_PUBLIC_URL, one setting for the
-- deployment, and a column that can disagree with it is worse than no column.
ALTER TABLE graph_app DROP COLUMN IF EXISTS notify_url;

-- Which Microsoft cloud the tenant lives in: public (the default) | usgov | usgovdod
-- | china. Added after the table shipped, so existing rows read as public, which is
-- what they were.
--
-- On the registration rather than as a connector flag, because two processes need it
-- now: the connector to reach the right API host, and the engine to walk the
-- directory. As a flag it also meant a GCC High deployment configured its cloud by
-- editing a compose file, which is the thing this table was created to stop.
ALTER TABLE graph_app ADD COLUMN IF NOT EXISTS cloud TEXT;

-- Rule feeds: detection content cloned from a git repository on a schedule.
--
-- A fresh install has no rules at all, because the corpus is somebody else's
-- repository and is not vendored into this one. The Sublime feed is seeded here on
-- first start so that a new deployment detects something out of the box, and an
-- operator can add their own — a team's private rules, a vendor's, a fork.
--
-- Content only. A feed supplies rules; it cannot supply actions, and nothing it
-- brings can act on a mailbox until an admin attaches an action to it here. That
-- boundary is what makes pulling from a third party a reasonable default rather
-- than a remote-code-execution hole with a schedule.
CREATE TABLE IF NOT EXISTS rule_feeds (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    url         TEXT NOT NULL,
    branch      TEXT NOT NULL DEFAULT '',   -- empty means the remote's default
    subdir      TEXT NOT NULL DEFAULT '',   -- load only this path within the repo

    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    every_secs  INTEGER NOT NULL DEFAULT 21600,

    -- An access token for a private repository, encrypted at rest exactly as a
    -- mailbox credential is, and readable by a service token only — never by a
    -- browser session.
    secret_enc  BYTEA,

    -- What the last sync found. last_error is kept rather than cleared so a feed
    -- that broke three days ago still says so.
    last_sync   TIMESTAMPTZ,
    last_commit TEXT NOT NULL DEFAULT '',
    last_error  TEXT NOT NULL DEFAULT '',
    rule_count  INTEGER NOT NULL DEFAULT 0,

    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS rule_feeds_due ON rule_feeds (enabled, last_sync);
