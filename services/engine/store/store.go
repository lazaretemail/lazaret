// SPDX-License-Identifier: AGPL-3.0-only

// Package store is lazaret-engine's persistence, as specified in docs/ADR-001-storage.md.
//
// Two systems, for two shapes of data:
//
//   - **Postgres** holds relational state — tenants, rules, the action log, hunt jobs —
//     and the materialised current sender profile that the delivery path reads. It is
//     also the DuckLake catalog, which is the reason DuckLake was chosen: the catalog is
//     an ordinary SQL database rather than a tree of metadata files, so one Postgres
//     does two jobs and the deployment gains no component.
//
//   - **DuckLake** holds the message corpus, the verdicts and the sender-event log:
//     wide, immutable, appended once and thereafter scanned. Parquet data files in the
//     blob store, catalog rows in Postgres, read and written through DuckDB linked into
//     this process.
//
// The division is not stylistic. 1,521 rule entities against every message is 228
// million (message, rule) pairs a day at 150,000 messages, and a sender profile must be
// answerable *as of* the message being evaluated or every backtest sees the future.
// Neither fits a row store; both fit an append-only columnar log.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lazaretemail/lazaret/internal/container"
)

//go:embed schema.sql
var schemaSQL string

// Options configure a Store.
type Options struct {
	// Postgres is a libpq connection string.
	Postgres string
	// DataPath is where DuckLake writes Parquet. A local directory, or an s3:// URL
	// when S3 is configured below.
	DataPath string
	// S3 configures the blob store. Optional: a local DataPath needs none of it, which
	// is what makes a single-node deployment possible without Garage.
	S3Endpoint  string
	S3Region    string
	S3AccessKey string
	S3SecretKey string
	// RawPath is where the original message bytes are held, for messages taken out
	// of a mailbox. A local directory, or s3://bucket/prefix.
	//
	// Separate from DataPath even when both are in the same blob store, because they
	// have different shapes and different lifetimes: DuckLake owns its prefix and
	// rewrites it during compaction, while these are individual objects that must
	// survive untouched until someone releases or purges them. Pointing this at the
	// corpus prefix would let a compaction expire mail under legal hold.
	RawPath string

	// TempPath is where DuckDB spills a query that does not fit in its memory
	// budget. Without one it has nowhere to go and fails the query instead, which
	// turns "this hunt is large" into "this hunt is broken". Optional: empty means
	// no spill directory, which is right for tests and wrong for a deployment.
	TempPath string
	S3UseSSL bool
	// ReadOnly opens the corpus without taking a write lock, for a hunt worker.
	ReadOnly bool
}

// Store is the engine's persistence.
type Store struct {
	pg   *pgxpool.Pool
	duck *sql.DB
	opts Options

	// secrets encrypts mailbox credentials at rest. Nil when no key is configured,
	// in which case storing one is refused rather than done in the clear.
	secrets *SecretBox

	// custody holds the original bytes of ingested messages. Nil when no raw path is
	// configured, in which case quarantine is refused rather than deleting mail that
	// could never be released.
	custody custody
}

// Open connects to Postgres, applies the schema, and attaches DuckLake.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Postgres == "" {
		return nil, fmt.Errorf("store: a postgres connection string is required")
	}
	if opts.DataPath == "" {
		return nil, fmt.Errorf("store: a data path is required for the message corpus")
	}

	pool, err := pgxpool.New(ctx, opts.Postgres)
	if err != nil {
		return nil, fmt.Errorf("store: connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: postgres unreachable: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: applying schema: %w", err)
	}

	duck, err := sql.Open("duckdb", "")
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: opening duckdb: %w", err)
	}
	if err := boundDuckDB(ctx, duck, opts.TempPath); err != nil {
		duck.Close()
		pool.Close()
		return nil, err
	}
	// DuckDB is linked into this process and every connection in the pool would need the
	// same extensions and the same ATTACH. One connection avoids that, and the corpus
	// workload is a handful of large scans rather than many small queries, so the
	// serialisation costs little. A hunt worker opens its own Store.
	duck.SetMaxOpenConns(1)

	s := &Store{pg: pool, duck: duck, opts: opts}

	// Custody before DuckLake, because a misconfigured blob store should be an error
	// while someone is watching and not the first time a message needs holding.
	cust, err := openCustody(ctx, opts.RawPath, opts)
	if err != nil {
		duck.Close()
		pool.Close()
		return nil, err
	}
	s.custody = cust

	if err := s.attachDuckLake(ctx); err != nil {
		duck.Close()
		pool.Close()
		return nil, err
	}
	if err := s.createCorpusTables(ctx); err != nil {
		duck.Close()
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases both connections.
func (s *Store) Close() error {
	var err error
	if s.duck != nil {
		err = s.duck.Close()
	}
	if s.pg != nil {
		s.pg.Close()
	}
	return err
}

// PG exposes the pool, for the parts of the service that speak SQL directly.
func (s *Store) PG() *pgxpool.Pool { return s.pg }

// Duck exposes the DuckDB handle, for hunt.
func (s *Store) Duck() *sql.DB { return s.duck }

// attachDuckLake points DuckDB at the Postgres catalog and the data path.
func (s *Store) attachDuckLake(ctx context.Context) error {
	for _, ext := range []string{"ducklake", "postgres", "httpfs"} {
		if _, err := s.duck.ExecContext(ctx, "INSTALL "+ext); err != nil {
			return fmt.Errorf("store: installing the duckdb %s extension: %w", ext, err)
		}
		if _, err := s.duck.ExecContext(ctx, "LOAD "+ext); err != nil {
			return fmt.Errorf("store: loading the duckdb %s extension: %w", ext, err)
		}
	}

	if s.opts.S3Endpoint != "" {
		// A CREATE SECRET rather than SET s3_access_key_id, so the credentials do not
		// appear in DuckDB's settings and thus in any diagnostic dump of them.
		secret := fmt.Sprintf(`CREATE OR REPLACE SECRET lazaret_s3 (
			TYPE s3, KEY_ID %s, SECRET %s, ENDPOINT %s, REGION %s, USE_SSL %t, URL_STYLE 'path')`,
			quote(s.opts.S3AccessKey), quote(s.opts.S3SecretKey),
			quote(s.opts.S3Endpoint), quote(cmp(s.opts.S3Region, "us-east-1")), s.opts.S3UseSSL)
		if _, err := s.duck.ExecContext(ctx, secret); err != nil {
			return fmt.Errorf("store: configuring s3: %w", err)
		}
	}

	attach := fmt.Sprintf("ATTACH IF NOT EXISTS 'ducklake:postgres:%s' AS corpus (DATA_PATH %s)",
		s.opts.Postgres, quote(ensureSlash(s.opts.DataPath)))
	if s.opts.ReadOnly {
		attach += ", READ_ONLY"
	}
	if _, err := s.duck.ExecContext(ctx, attach); err != nil {
		return fmt.Errorf("store: attaching ducklake: %w", err)
	}
	return nil
}

// createCorpusTables defines the append-only tables.
//
// No primary keys and no indexes, deliberately: DuckLake has neither, and both would be
// the wrong shape anyway. These are scanned with a tenant and date predicate, which
// partition pruning answers, not looked up by key.
func (s *Store) createCorpusTables(ctx context.Context) error {
	if s.opts.ReadOnly {
		return nil
	}
	stmts := []string{
		// One row per message. The MDM is stored whole as JSON rather than shredded into
		// columns: rules read 54,740 distinct field paths across the corpus, so any
		// column set narrow enough to be worth having would be one a rule reaches past.
		`CREATE TABLE IF NOT EXISTS corpus.messages (
			tenant_id     VARCHAR NOT NULL,
			message_id    VARCHAR NOT NULL,
			received_at   TIMESTAMPTZ NOT NULL,
			day           DATE NOT NULL,
			sender_email  VARCHAR,
			sender_domain VARCHAR,
			subject       VARCHAR,
			direction     VARCHAR,
			verdict       VARCHAR,
			mdm           VARCHAR NOT NULL,
			raw_key       VARCHAR,
			-- Who it was addressed to. Needed for $recipient_emails and
			-- $recipient_domains, which 63 rules between them use to ask "is this
			-- one of ours".
			recipients    VARCHAR[],
			-- What the analysis concluded, stored rather than recomputed.
			--
			-- The detail view used to re-run all 1,257 rules on every page load,
			-- which meant a fresh RDAP lookup, a fresh classifier pass and a fresh
			-- visit to every link each time somebody clicked a message. Five
			-- seconds, real network traffic to the attacker's infrastructure, and
			-- an answer that could differ from the one the verdict was based on.
			--
			-- Stored at ingest, read on view. Re-evaluation is still available and
			-- still useful — an analyst tuning a rule wants to see its effect — but
			-- it is now something you ask for rather than something every click
			-- pays for.
			analysis      VARCHAR,

			-- What enrichment answered, frozen: a serialised mql.Snapshot.
			--
			-- analysis above is the conclusion; this is the evidence. Keeping it is
			-- what lets a rule be run again over old mail without re-fetching — which
			-- is not merely expensive but wrong, since the link is dead by then and
			-- the WHOIS record has moved, so a re-fetch answers a question about March
			-- with October's facts.
			--
			-- It is the larger of the two by a wide margin, and it is mostly the JSON
			-- the enrichers returned, which Parquet and zstd handle well.
			evidence      VARCHAR,

			-- A 64-bit SimHash over the message's structure, for grouping one attack
			-- that arrived thirty times. Computed at ingest because it needs the
			-- parsed model and costs microseconds; stored because clustering a month
			-- of mail must not mean re-parsing a month of mail.
			--
			-- Signed, because Parquet and DuckDB have no unsigned 64-bit type worth
			-- relying on. The value is the same sixty-four bits either way, and only
			-- equality and XOR are ever done with it.
			fingerprint   BIGINT
		)`,
		// Added after the table shipped. DuckLake takes ALTER TABLE, and an
		// existing deployment should gain the column rather than need a rebuild.
		`ALTER TABLE corpus.messages ADD COLUMN IF NOT EXISTS analysis VARCHAR`,
		`ALTER TABLE corpus.messages ADD COLUMN IF NOT EXISTS evidence VARCHAR`,
		`ALTER TABLE corpus.messages ADD COLUMN IF NOT EXISTS fingerprint BIGINT`,
		// One row per message, not per (message, rule). Matches are a list and the
		// indeterminate set is a list: 1,521 rules against every message would be 228
		// million pairs a day, and the cross product is never the question anyone asks.
		`CREATE TABLE IF NOT EXISTS corpus.verdicts (
			tenant_id     VARCHAR NOT NULL,
			message_id    VARCHAR NOT NULL,
			day           DATE NOT NULL,
			verdict       VARCHAR NOT NULL,
			matched       VARCHAR[],
			indeterminate VARCHAR[],
			missing       VARCHAR[],
			evaluated_at  TIMESTAMPTZ NOT NULL
		)`,
		// The source of truth for profiles. Append-only, so it can answer "as of" for
		// any moment; the Postgres table above is a derived view of it for "now".
		`CREATE TABLE IF NOT EXISTS corpus.sender_events (
			tenant_id     VARCHAR NOT NULL,
			occurred_at   TIMESTAMPTZ NOT NULL, -- not "at": reserved in DuckDB
			day           DATE NOT NULL,
			sender_email  VARCHAR,
			sender_domain VARCHAR,
			reply_to      VARCHAR,
			direction     VARCHAR NOT NULL,
			verdict       VARCHAR,
			auth_failed   BOOLEAN NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.duck.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: creating corpus tables: %w", err)
		}
	}
	return nil
}

// EnsureTenant creates a tenant if it does not exist.
// A nil orgConfig means "do not touch the configuration", not "set it to empty".
//
// This is called on every startup to make sure the tenant row exists, and the first
// version of it passed EXCLUDED.org_config unconditionally. That made each restart
// reset the organisation configuration to {} — so an admin set their domains in the
// UI, the service was restarted, and the 138 rules gated on $org_domains went quietly
// indeterminate with nothing logged. Seeding is a separate, explicit call.
func (s *Store) EnsureTenant(ctx context.Context, id, name string, orgConfig []byte) error {
	if len(orgConfig) == 0 {
		_, err := s.pg.Exec(ctx, `
			INSERT INTO tenants (id, name) VALUES ($1, $2)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
			id, name)
		return err
	}
	_, err := s.pg.Exec(ctx, `
		INSERT INTO tenants (id, name, org_config) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, org_config = EXCLUDED.org_config`,
		id, name, orgConfig)
	return err
}

// OrgConfig returns a tenant's configuration.
func (s *Store) OrgConfig(ctx context.Context, tenant string) ([]byte, error) {
	var raw []byte
	err := s.pg.QueryRow(ctx, `SELECT org_config FROM tenants WHERE id = $1`, tenant).Scan(&raw)
	return raw, err
}

// RecordAction appends to the audit log.
//
// The thing the project is named for: what was quarantined, what was released, who
// decided. There is no update path, because an audit trail that can be edited is not one.
func (s *Store) RecordAction(ctx context.Context, tenant, messageID, action, reason, actor string) error {
	_, err := s.pg.Exec(ctx,
		`INSERT INTO actions (tenant_id, message_id, action, reason, actor) VALUES ($1,$2,$3,$4,$5)`,
		tenant, messageID, action, reason, actor)
	return err
}

// Action is one entry in the audit log.
type Action struct {
	Action    string    `json:"action"`
	Reason    string    `json:"reason,omitempty"`
	Actor     string    `json:"actor"`
	At        time.Time `json:"at"`
	MessageID string    `json:"message_id"`
}

// Actions returns the audit log for a message.
func (s *Store) Actions(ctx context.Context, tenant, messageID string) ([]Action, error) {
	rows, err := s.pg.Query(ctx,
		`SELECT action, coalesce(reason,''), actor, at, message_id
		 FROM actions WHERE tenant_id = $1 AND message_id = $2 ORDER BY at`,
		tenant, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Action
	for rows.Next() {
		var a Action
		if err := rows.Scan(&a.Action, &a.Reason, &a.Actor, &a.At, &a.MessageID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// quote renders a SQL string literal.
//
// DuckDB's ATTACH and CREATE SECRET take literals rather than parameters, so these
// cannot be bound. Every value reaching here is operator configuration rather than
// anything from a message, but doubling the quote costs nothing and means a path with
// an apostrophe in it is a broken path rather than a broken statement.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func cmp(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func ensureSlash(p string) string {
	if strings.HasSuffix(p, "/") {
		return p
	}
	return p + "/"
}

// OpenIdentityOnly connects to Postgres without attaching the corpus.
//
// Administrative tasks — issuing a token, creating the first account — need identity
// and nothing else, and requiring the corpus for them means an operator cannot mint a
// credential unless DuckLake attaches cleanly. Since a DuckLake catalog is bound to
// its data path, that turned "issue a token" into "know the exact data path", which is
// a needless coupling for a task that never touches a message.
func OpenIdentityOnly(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: postgres unreachable: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: applying schema: %w", err)
	}
	return &Store{pg: pool}, nil
}

// How much of the engine's container DuckDB may take, and what to assume when
// there is no container to ask.
//
// DuckDB defaults memory_limit to 80% of *system* RAM and threads to the machine's
// core count. Both are the wrong question in a compose stack: on a 30GB host this
// service would size itself at 24GB while sharing the box with twelve other
// containers, and nothing in the engine would ever report a problem — it would
// just be the reason the machine had no memory left. Sublime's own self-hosted
// deployment is remembered for exactly that shape of pressure, and defaults like
// this one are how it happens.
//
// A third, because the rest of the engine is not small: 1,258 compiled rules, the
// $list data, the enricher caches and the Go heap all live in the same container.
const (
	duckMemoryShare    = 0.33
	duckMemoryFallback = 2 << 30 // no cgroup limit: modest, not a share of the host
	duckMemoryMin      = 512 << 20
	duckMemoryMax      = 16 << 30
)

// boundDuckDB sizes DuckDB to the container instead of to the machine.
func boundDuckDB(ctx context.Context, duck *sql.DB, temp string) error {
	budget := container.Budget(duckMemoryShare, duckMemoryFallback, duckMemoryMin, duckMemoryMax)
	threads := container.CPUs()

	pragmas := []string{
		fmt.Sprintf("SET memory_limit = '%dMB'", budget>>20),
		fmt.Sprintf("SET threads = %d", threads),
	}
	// A bound with nowhere to spill turns a large query into a failed one, so the
	// two go together: the limit is what stops the engine eating the host, and the
	// spill directory is what keeps a big hunt working anyway, slowly.
	if temp != "" {
		if err := os.MkdirAll(temp, 0o700); err != nil {
			return fmt.Errorf("store: duckdb spill directory: %w", err)
		}
		pragmas = append(pragmas, fmt.Sprintf("SET temp_directory = '%s'", temp))
	}
	for _, pragma := range pragmas {
		if _, err := duck.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("store: %s: %w", pragma, err)
		}
	}
	log.Printf("store: duckdb bounded to %dMB and %d thread(s)%s",
		budget>>20, threads, duckBoundedBecause())
	return nil
}

func duckBoundedBecause() string {
	if limit := container.MemoryLimit(); limit > 0 {
		return fmt.Sprintf(" — a third of this container's %dMB", limit>>20)
	}
	return " — no container limit to read, so a fixed default rather than a share of the host"
}
