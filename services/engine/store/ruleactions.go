// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lazaretemail/lazaret/actions"
)

// Configured actions, and which rules use them.
//
// Nothing here fires until an administrator both creates an action and attaches it
// to a rule. See package actions for why the default is to do nothing at all.

// ConfiguredAction is an action instance as stored.
//
// Named at length to leave Action alone: that is an entry in the audit log, which
// is a different thing — what was done to one message, rather than what this
// deployment is set up to do.
type ConfiguredAction struct {
	actions.Instance
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`

	// Rules is how many rules use it, so removing one says what it will stop.
	Rules int `json:"rules"`
}

// SaveAction creates or updates a configured action.
func (s *Store) SaveAction(ctx context.Context, tenant string, in actions.Instance, by string) (*ConfiguredAction, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	cfg, err := json.Marshal(in.Config)
	if err != nil {
		return nil, err
	}

	id := in.ID
	if id == "" {
		if id, err = randomID("act"); err != nil {
			return nil, err
		}
	}
	_, err = s.pg.Exec(ctx, `
		INSERT INTO action_configs (id, tenant_id, label, type, config, enabled, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''))
		ON CONFLICT (id) DO UPDATE SET
		  label = EXCLUDED.label, config = EXCLUDED.config,
		  enabled = EXCLUDED.enabled, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		id, tenant, in.Label, string(in.Type), cfg, in.Enabled, by)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, errors.New("store: an action with that label already exists")
		}
		return nil, err
	}
	return s.ActionByID(ctx, tenant, id)
}

// The type is deliberately not updatable above. Changing what an action *is* under
// a thousand rules that were attached to it is not an edit, it is a different
// decision — and the rules would follow it silently. Delete and create instead.

// ActionByID returns one configured action.
func (s *Store) ActionByID(ctx context.Context, tenant, id string) (*ConfiguredAction, error) {
	row := s.pg.QueryRow(ctx, `
		SELECT a.id, a.label, a.type, a.config, a.enabled, a.updated_at,
		       coalesce(a.updated_by,''),
		       (SELECT count(*) FROM rule_actions r WHERE r.action_id = a.id)
		FROM action_configs a WHERE a.tenant_id = $1 AND a.id = $2`, tenant, id)
	return scanAction(row)
}

// ConfiguredActions lists every configured action.
//
// Not Actions, which already reads the audit log for one message.
func (s *Store) ConfiguredActions(ctx context.Context, tenant string) ([]ConfiguredAction, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT a.id, a.label, a.type, a.config, a.enabled, a.updated_at,
		       coalesce(a.updated_by,''),
		       (SELECT count(*) FROM rule_actions r WHERE r.action_id = a.id)
		FROM action_configs a WHERE a.tenant_id = $1 ORDER BY lower(a.label)`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ConfiguredAction
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func scanAction(row pgx.Row) (*ConfiguredAction, error) {
	var (
		a   ConfiguredAction
		typ string
		cfg []byte
	)
	if err := row.Scan(&a.ID, &a.Label, &typ, &cfg, &a.Enabled,
		&a.UpdatedAt, &a.UpdatedBy, &a.Rules); err != nil {
		return nil, err
	}
	a.Type = actions.Type(typ)
	if len(cfg) > 0 {
		_ = json.Unmarshal(cfg, &a.Config)
	}
	return &a, nil
}

// DeleteAction removes a configured action, and with it every rule's use of it.
//
// The cascade is the point: an action that no longer exists must not leave rows
// behind pointing at it, and a rule silently attached to nothing is worse than a
// rule an administrator can see is attached to nothing.
func (s *Store) DeleteAction(ctx context.Context, tenant, id string) error {
	_, err := s.pg.Exec(ctx, `DELETE FROM action_configs WHERE tenant_id=$1 AND id=$2`, tenant, id)
	return err
}

// RuleActions returns the enabled actions for every rule that has any.
//
// The whole map rather than one rule at a time: the caller is either rendering a
// thousand rules or deciding about a message that matched several, and both want
// one query. Disabled instances are left out here rather than filtered later, so
// the off switch works everywhere at once.
func (s *Store) RuleActions(ctx context.Context, tenant string) (map[string][]ConfiguredAction, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT r.rule_id, a.id, a.label, a.type, a.config, a.enabled, a.updated_at,
		       coalesce(a.updated_by,''), 0
		FROM rule_actions r
		JOIN action_configs a ON a.id = r.action_id
		WHERE r.tenant_id = $1 AND a.enabled
		ORDER BY r.rule_id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string][]ConfiguredAction{}
	for rows.Next() {
		var ruleID string
		var a ConfiguredAction
		var typ string
		var cfg []byte
		if err := rows.Scan(&ruleID, &a.ID, &a.Label, &typ, &cfg, &a.Enabled,
			&a.UpdatedAt, &a.UpdatedBy, &a.Rules); err != nil {
			return nil, err
		}
		a.Type = actions.Type(typ)
		if len(cfg) > 0 {
			_ = json.Unmarshal(cfg, &a.Config)
		}
		out[ruleID] = append(out[ruleID], a)
	}
	return out, rows.Err()
}

// AttachActions adds actions to rules, for the bulk control.
func (s *Store) AttachActions(ctx context.Context, tenant string, ruleIDs, actionIDs []string, by string) error {
	if len(ruleIDs) == 0 || len(actionIDs) == 0 {
		return nil
	}
	_, err := s.pg.Exec(ctx, `
		INSERT INTO rule_actions (tenant_id, rule_id, action_id, added_by)
		SELECT $1, r, a, NULLIF($4,'')
		FROM unnest($2::text[]) r CROSS JOIN unnest($3::text[]) a
		WHERE EXISTS (SELECT 1 FROM action_configs x WHERE x.id = a AND x.tenant_id = $1)
		ON CONFLICT DO NOTHING`, tenant, ruleIDs, actionIDs, by)
	return err
}

// DetachActions takes actions off rules.
func (s *Store) DetachActions(ctx context.Context, tenant string, ruleIDs, actionIDs []string) error {
	if len(ruleIDs) == 0 || len(actionIDs) == 0 {
		return nil
	}
	_, err := s.pg.Exec(ctx, `
		DELETE FROM rule_actions
		WHERE tenant_id = $1 AND rule_id = ANY($2) AND action_id = ANY($3)`,
		tenant, ruleIDs, actionIDs)
	return err
}
