// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Custody in object storage, against a real S3 server.
//
// Not mocked. The interesting behaviour is all in how a real server answers — whether
// a missing object comes back as a typed NoSuchKey or a bare 404, whether HeadObject
// reports a size, whether path-style addressing is needed — and a fake can only
// confirm what its author already believed. The same reasoning as the DuckLake tests.
//
//	docker run -d --name lazaret-garage --network host \
//	  -v ./garage.toml:/etc/garage.toml:ro dxflrs/garage:v1.0.1
//	LAZARET_TEST_S3=localhost:3900 LAZARET_TEST_S3_KEY=... LAZARET_TEST_S3_SECRET=... \
//	  go test ./store -run S3
func s3Store(t *testing.T) *store.Store {
	t.Helper()
	endpoint := os.Getenv("LAZARET_TEST_S3")
	if endpoint == "" {
		t.Skip("set LAZARET_TEST_S3 to run the object-storage custody tests")
	}
	dsn, dir := isolated(t)
	s, err := store.Open(context.Background(), store.Options{
		Postgres: dsn, DataPath: dir,
		// A prefix per test, so tests cannot see each other's held messages.
		RawPath:     "s3://" + os.Getenv("LAZARET_TEST_S3_BUCKET") + "/" + t.Name(),
		S3Endpoint:  endpoint,
		S3Region:    "garage",
		S3AccessKey: os.Getenv("LAZARET_TEST_S3_KEY"),
		S3SecretKey: os.Getenv("LAZARET_TEST_S3_SECRET"),
	})
	if err != nil {
		t.Fatalf("opening the store against %s: %v", endpoint, err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestS3CustodyRoundTrip(t *testing.T) {
	s := s3Store(t)
	ctx := context.Background()

	raw := []byte("Message-ID: <a@b.test>\r\nSubject: held\r\n\r\nbody\r\n")

	if s.HasRaw(ctx, "t", "a@b.test") {
		t.Fatal("reports holding a message it was never given")
	}
	if _, err := s.Raw(ctx, "t", "a@b.test"); err != store.ErrNoRaw {
		t.Fatalf("reading an unheld message: got %v, want ErrNoRaw", err)
	}

	if err := s.PutRaw(ctx, "t", "a@b.test", raw); err != nil {
		t.Fatal(err)
	}
	if !s.HasRaw(ctx, "t", "a@b.test") {
		t.Error("does not report holding a message it was just given")
	}
	got, err := s.Raw(ctx, "t", "a@b.test")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Errorf("the bytes changed in custody:\n got %q\nwant %q", got, raw)
	}

	if err := s.PurgeRaw(ctx, "t", "a@b.test"); err != nil {
		t.Fatal(err)
	}
	if s.HasRaw(ctx, "t", "a@b.test") {
		t.Error("still holding a purged message")
	}
	// Purging twice is not an error: an operator clicking delete on an already
	// deleted message has got what they wanted.
	if err := s.PurgeRaw(ctx, "t", "a@b.test"); err != nil {
		t.Errorf("purging twice: %v", err)
	}
}

// The same traversal check as the filesystem backend. An object key is not a path, so
// "../" does not escape a bucket — but it does produce a key the caller did not
// intend, and one a sender chose.
func TestS3CustodyKeysAreHashed(t *testing.T) {
	s := s3Store(t)
	ctx := context.Background()

	for _, id := range []string{
		"../../../../etc/passwd",
		"/absolute/key",
		strings.Repeat("a", 4096),
		"with\x00nul",
		"..",
	} {
		if err := s.PutRaw(ctx, "t", id, []byte("x")); err != nil {
			t.Errorf("PutRaw(%.24q): %v", id, err)
			continue
		}
		got, err := s.Raw(ctx, "t", id)
		if err != nil {
			t.Errorf("Raw(%.24q): %v", id, err)
			continue
		}
		if string(got) != "x" {
			t.Errorf("Raw(%.24q) = %q", id, got)
		}
	}
}

func TestS3CustodyIsPerTenant(t *testing.T) {
	s := s3Store(t)
	ctx := context.Background()
	if err := s.PutRaw(ctx, "one", "shared@b.test", []byte("tenant one")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRaw(ctx, "two", "shared@b.test", []byte("tenant two")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Raw(ctx, "one", "shared@b.test"); string(got) != "tenant one" {
		t.Errorf("tenant one read %q", got)
	}
	if got, _ := s.Raw(ctx, "two", "shared@b.test"); string(got) != "tenant two" {
		t.Errorf("tenant two read %q", got)
	}
}

// A large message must survive whole. Quarantine deletes the original, so a truncated
// held copy is a lost message rather than a degraded one.
func TestS3CustodyHoldsALargeMessage(t *testing.T) {
	s := s3Store(t)
	ctx := context.Background()

	body := strings.Repeat("attachment data 0123456789\r\n", 400_000) // ~11MB
	raw := []byte("Message-ID: <big@b.test>\r\nSubject: big\r\n\r\n" + body)

	if err := s.PutRaw(ctx, "t", "big@b.test", raw); err != nil {
		t.Fatal(err)
	}
	got, err := s.Raw(ctx, "t", "big@b.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(raw) {
		t.Fatalf("held %d bytes of a %d byte message", len(got), len(raw))
	}
	if string(got) != string(raw) {
		t.Error("the bytes changed in custody")
	}
}
