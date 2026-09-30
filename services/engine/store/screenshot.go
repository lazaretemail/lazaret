// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
)

// The screenshot cache.
//
// Rendering a message costs a browser launch, so the picture is kept. It is a cache and
// deliberately not custody: custody holds the only copy of a quarantined message, and a
// regenerable artifact stored beside it is an invitation for a purge to take the wrong
// object, or for a restore to hand back a PNG.

// ErrNoScreenshot means nothing is cached for this message yet.
var ErrNoScreenshot = errors.New("store: no screenshot cached")

// ScreenshotDigest identifies the input a picture was made from.
func ScreenshotDigest(html []byte) string {
	sum := sha256.Sum256(html)
	return hex.EncodeToString(sum[:16])
}

// Screenshot returns the cached picture, if one was made from this exact input.
//
// The digest is checked rather than trusted: a message re-parsed by a newer engine can
// produce different HTML, and serving the previous picture of it would show an analyst
// something the current model does not say.
func (s *Store) Screenshot(ctx context.Context, tenant, messageID, digest string) ([]byte, error) {
	var png []byte
	err := s.pg.QueryRow(ctx,
		`SELECT png FROM screenshots WHERE tenant_id = $1 AND message_id = $2 AND digest = $3`,
		tenant, messageID, digest).Scan(&png)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoScreenshot
	}
	return png, err
}

// SetScreenshot caches a rendered picture.
func (s *Store) SetScreenshot(ctx context.Context, tenant, messageID, digest string, png []byte) error {
	_, err := s.pg.Exec(ctx, `
		INSERT INTO screenshots (tenant_id, message_id, digest, png, at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (tenant_id, message_id) DO UPDATE
		  SET digest = EXCLUDED.digest, png = EXCLUDED.png, at = now()`,
		tenant, messageID, digest, png)
	return err
}
