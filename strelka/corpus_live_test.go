// SPDX-License-Identifier: AGPL-3.0-only

package strelka_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/eml"
	"github.com/lazaretemail/lazaret/internal/corpus"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/orgconfig"
	"github.com/lazaretemail/lazaret/strelka"
)

// What deploying Strelka is actually worth, measured rather than asserted.
//
// The corpus evaluation in mql/ runs with no enricher, so every rule that calls
// file.explode or file.expand_archives reports indeterminate — correctly, since an
// unavailable capability is not a false. This runs the same corpus twice, once without
// Strelka and once with it, and reports how many entities move off indeterminate.
//
// It lives here rather than in mql/ because mql cannot import strelka: strelka imports
// mql for its value types, so the dependency only runs one way.
//
// Opt-in, like the other live test:
//
//	LAZARET_STRELKA=localhost:57314 go test ./strelka/ -run LiveCorpus -v
func TestLiveCorpusGainsFromStrelka(t *testing.T) {
	addr := os.Getenv("LAZARET_STRELKA")
	if addr == "" {
		t.Skip("set LAZARET_STRELKA to a Strelka frontend address to run this")
	}
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}

	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}
	messages := loadCorpusMessages(t)
	if len(messages) == 0 {
		t.Skip("no sample messages in the corpus checkout")
	}
	// None of the corpus's six sample messages carries an attachment, so every
	// file.explode call short-circuits on an empty `attachments` and Strelka can
	// contribute nothing. Measuring the gain needs a message with a file on it.
	messages = append(messages, messageWithRealArchive(t), messageWithQRImage(t))

	c, err := strelka.Dial(&strelka.Options{Address: addr, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	// Wrapped in a cache, as any real caller must be: ~500 corpus rules each write
	// `file.explode(.)` for themselves, and without memoisation one message costs a
	// thousand identical scans of the same bytes. Uncached, this measurement does not
	// finish inside a ten-minute test timeout.
	withStrelka := mql.NewCache(mql.NewMux().Handle(c, strelka.Capabilities()...))

	type counts struct{ match, noMatch, indeterminate int }
	run := func(e mql.Enricher) (counts, map[string]int) {
		var n counts
		stillMissing := map[string]int{}
		ctx := context.Background()
		for _, ent := range entities {
			if ent.Type == "triage_rule" {
				continue
			}
			checked, err := mql.Compile(ent.Source, nil)
			if err != nil {
				continue
			}
			for _, msg := range messages {
				res := mql.Eval(ctx, checked, msg, &mql.EvalOptions{Enricher: e})
				switch {
				case res.Err != nil:
					// Counted by the corpus tests in mql/; not this test's subject.
				case res.Verdict == mql.Match:
					n.match++
				case res.Verdict == mql.Indeterminate:
					n.indeterminate++
					for _, cap := range res.Missing {
						stillMissing[string(cap)]++
					}
				default:
					n.noMatch++
				}
			}
		}
		return n, stillMissing
	}

	before, _ := run(nil)
	after, missing := run(withStrelka)

	t.Logf("without strelka: %d match, %d no-match, %d indeterminate",
		before.match, before.noMatch, before.indeterminate)
	t.Logf("with strelka:    %d match, %d no-match, %d indeterminate",
		after.match, after.noMatch, after.indeterminate)
	t.Logf("resolved by strelka: %d evaluations moved off indeterminate",
		before.indeterminate-after.indeterminate)

	// The capabilities still missing should no longer include the two Strelka answers.
	for _, cap := range strelka.Capabilities() {
		if n := missing[string(cap)]; n > 0 {
			t.Errorf("%s still reported missing %d times with Strelka connected", cap, n)
		}
	}

	if after.indeterminate >= before.indeterminate {
		t.Errorf("connecting Strelka resolved nothing: %d indeterminate before, %d after",
			before.indeterminate, after.indeterminate)
	}

	// Sanity: Strelka must not have turned a definite verdict into an indeterminate one,
	// and the rules it unblocks should be reaching real answers.
	if after.match+after.noMatch <= before.match+before.noMatch {
		t.Errorf("definite verdicts did not increase: %d before, %d after",
			before.match+before.noMatch, after.match+after.noMatch)
	}

	// Report what is still unanswered, so the next module has a target.
	type kv struct {
		cap string
		n   int
	}
	var rest []kv
	for k, v := range missing {
		rest = append(rest, kv{k, v})
	}
	slices.SortFunc(rest, func(a, b kv) int { return b.n - a.n })
	for i, r := range rest {
		if i >= 10 {
			break
		}
		t.Logf("still missing: %-28s %d", r.cap, r.n)
	}
}

// messageWithRealArchive builds a message carrying a zip with a script in it — the shape
// file.explode exists for. It is constructed rather than committed because the corpus
// ships no attachment sample and testdata/ is not tracked.
func messageWithRealArchive(t *testing.T) *mdm.MessageDataModel {
	t.Helper()

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	for _, f := range []struct{ name, body string }{
		{"invoice.txt", "an urgent payment request"},
		{"script.js", `var x = unescape("%41%42"); eval(x);`},
	} {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var raw bytes.Buffer
	raw.WriteString("From: Accounts <billing@vendor.example>\r\n")
	raw.WriteString("To: ap@example.com\r\n")
	raw.WriteString("Subject: Invoice attached\r\n")
	raw.WriteString("Date: Mon, 2 Jun 2025 09:00:00 +0000\r\n")
	raw.WriteString("MIME-Version: 1.0\r\n")
	raw.WriteString("Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n")
	raw.WriteString("--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	raw.WriteString("Please see the attached invoice.\r\n\r\n")
	raw.WriteString("--b1\r\n")
	raw.WriteString("Content-Type: application/zip; name=\"invoice.zip\"\r\n")
	raw.WriteString("Content-Disposition: attachment; filename=\"invoice.zip\"\r\n")
	raw.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString(zipBuf.Bytes())
	for i := 0; i < len(enc); i += 76 {
		raw.WriteString(enc[i:min(i+76, len(enc))] + "\r\n")
	}
	raw.WriteString("--b1--\r\n")

	org := &orgconfig.Config{Domains: []string{"example.com"}}
	org.Normalize()
	m, err := eml.Parse(raw.Bytes(), &eml.Options{Org: org})
	if err != nil {
		t.Fatalf("parsing the synthetic message: %v", err)
	}
	if len(m.Attachments) == 0 {
		t.Fatal("the synthetic message has no attachment")
	}
	return m
}

func loadCorpusMessages(t *testing.T) []*mdm.MessageDataModel {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(corpus.Dir(), "emls", "*.eml"))
	if err != nil || len(paths) == 0 {
		return nil
	}
	org := &orgconfig.Config{Domains: []string{"example.com", "sublimesecurity.com"}}
	org.Normalize()

	var out []*mdm.MessageDataModel
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		m, err := eml.Parse(raw, &eml.Options{Org: org})
		if err != nil {
			t.Errorf("parsing %s: %v", p, err)
			continue
		}
		out = append(out, m)
	}
	return out
}

// messageWithQRImage carries the shape the image scanners exist for: a PNG attachment
// that is a QR code pointing at a credential-harvesting URL.
//
// Without it the measurement is dishonest. The archive message above never reaches an
// image, so beta.ocr, beta.scan_qr and the exiftool half of file.explode cannot fire, and
// reporting their gain against it would report roughly zero for capabilities that do
// real work — the same mistake as counting rules that merely *mention* a function.
func messageWithQRImage(t *testing.T) *mdm.MessageDataModel {
	t.Helper()

	png, err := os.ReadFile("testdata/qr.png")
	if err != nil {
		t.Fatalf("reading the QR fixture: %v", err)
	}
	pdf, err := os.ReadFile("testdata/invoice.pdf")
	if err != nil {
		t.Fatalf("reading the PDF fixture: %v", err)
	}

	return &mdm.MessageDataModel{
		Type: &mdm.MessageType{Inbound: mdm.Ptr(true), Outbound: mdm.Ptr(false), Internal: mdm.Ptr(false)},
		Sender: &mdm.SenderMailbox{
			DisplayName: mdm.Ptr("Accounts Payable"),
			Email:       mdm.ParseEmailAddress("billing@invoices.test"),
		},
		Subject:    &mdm.Subject{Subject: mdm.Ptr("Invoice overdue - scan to pay"), Base: mdm.Ptr("Invoice overdue - scan to pay")},
		Recipients: &mdm.Recipients{To: []*mdm.Mailbox{{Email: mdm.ParseEmailAddress("ap@example.com")}}},
		Headers:    &mdm.Headers{MessageID: mdm.Ptr("qr@invoices.test")},
		Body: &mdm.Body{
			CurrentThread: &mdm.Thread{Text: mdm.Ptr("Please scan the code to settle the attached invoice.")},
			Plain:         &mdm.Plain{Raw: mdm.Ptr("Please scan the code to settle the attached invoice.")},
		},
		Attachments: []*mdm.Attachment{
			{FileName: mdm.Ptr("payment-code.png"), FileExtension: mdm.Ptr("png"), ContentType: mdm.Ptr("image/png"), Size: mdm.Ptr(int64(len(png))), Raw: png},
			{FileName: mdm.Ptr("invoice.pdf"), FileExtension: mdm.Ptr("pdf"), ContentType: mdm.Ptr("application/pdf"), Size: mdm.Ptr(int64(len(pdf))), Raw: pdf},
		},
	}
}
