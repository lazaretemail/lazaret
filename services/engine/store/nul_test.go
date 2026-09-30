// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"testing"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// TestNULInAnyColumn covers a denial of service reachable from a message header.
//
// A DuckLake catalog is a Postgres database, and DuckLake reaches it by composing SQL
// text and calling postgres_execute. A NUL byte terminates that text early, so one
// crafted address failed the whole transaction with a syntax error quoting a fragment
// of an unrelated row — and, for a value used as a query parameter, failed reads as
// well, because the catalog pushdown concatenates those too. A sender who can stop the
// corpus accepting mail has stopped the platform recording what they sent.
//
// Each column separately, because the two that failed originally (a list element, and
// the id used for the duplicate check) failed at different layers, and a test that
// only exercised one would have been passed by half a fix.
func TestNULInAnyColumn(t *testing.T) {
	bad := "nul\x00byte"
	for _, tc := range []struct {
		name string
		mut  func(*store.Message)
	}{
		{"subject", func(m *store.Message) { m.Subject = bad }},
		{"sender_email", func(m *store.Message) { m.SenderEmail = bad + "@e.test" }},
		{"mdm", func(m *store.Message) { m.MDM = []byte(`{"s":"nul` + "\x00" + `byte"}`) }},
		{"message_id", func(m *store.Message) { m.MessageID = bad }},
		{"recipients", func(m *store.Message) { m.Recipients = []string{bad + "@e.test"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openStore(t)
			ctx := context.Background()
			if err := s.EnsureTenant(ctx, "t", "t", nil); err != nil {
				t.Fatal(err)
			}
			at := day(2)
			m := store.Message{TenantID: "t", MessageID: "m1", ReceivedAt: at,
				SenderEmail: "a@b.test", SenderDomain: "b.test", Subject: "s",
				Direction: "inbound", MDM: []byte(`{}`)}
			tc.mut(&m)
			err := s.PutMessage(ctx, m,
				store.Verdict{TenantID: "t", MessageID: m.MessageID, At: at, Verdict: "clean"},
				store.SenderEvent{TenantID: "t", At: at, SenderEmail: "a@b.test", SenderDomain: "b.test"})
			if err != nil {
				t.Errorf("a NUL in %s failed the write: %v", tc.name, err)
			}
		})
	}
}
