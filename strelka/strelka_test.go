// SPDX-License-Identifier: AGPL-3.0-only

package strelka_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/strelka"
	pb "github.com/lazaretemail/lazaret/strelka/strelkapb"
)

// fakeFrontend stands in for a Strelka deployment.
//
// The generated code includes a server interface, so the whole protocol can be exercised
// in-process over a bufconn: no container, no network, no port. Which matters here
// because the alternative — testing against a real Strelka — would make this suite
// depend on Docker and quietly get skipped.
type fakeFrontend struct {
	pb.UnimplementedFrontendServer

	// events are returned as the scan result, one per extracted file.
	events []string

	// err, if set, is returned instead.
	err error

	// delay before responding, for timeout tests.
	delay time.Duration

	mu       sync.Mutex
	received []byte
	filename string
	client   string
	calls    int
}

func (f *fakeFrontend) ScanFile(stream pb.Frontend_ScanFileServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.received = append(f.received, req.GetData()...)
		if a := req.GetAttributes(); a != nil && a.GetFilename() != "" {
			f.filename = a.GetFilename()
		}
		if r := req.GetRequest(); r != nil && r.GetClient() != "" {
			f.client = r.GetClient()
		}
		f.mu.Unlock()
	}

	f.mu.Lock()
	f.calls++
	f.mu.Unlock()

	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.err != nil {
		return f.err
	}
	for _, e := range f.events {
		if err := stream.Send(&pb.ScanResponse{Id: "scan-1", Event: e}); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeFrontend) body() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.received...)
}

// newFake starts the fake over an in-memory connection.
func newFake(t *testing.T, srv *fakeFrontend, opts *strelka.Options) *strelka.Client {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	pb.RegisterFrontendServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dialling the fake: %v", err)
	}

	t.Cleanup(func() {
		conn.Close()
		grpcServer.Stop()
		lis.Close()
	})
	return strelka.NewWithConn(conn, opts)
}

// Captured from a real Strelka (target/strelka-backend:latest) scanning a zip containing
// a text file and a script.
//
// These are the wire format, not Sublime's published FileExplodeOutput: metadata is
// nested under `file`, the tree is `file.tree.{node,parent}`, and `flavors.mime` is a
// list. An earlier version of this file used the published shape, and every test here
// passed against a fake that was lying — the mismatch only surfaced when a real Strelka
// returned records whose every field but `scan` was empty. Fixtures for a translation
// layer have to come from the thing being translated.
var archiveEvents = []string{
	`{"file":{"depth":0,"flavors":{"mime":["application/zip"],"yara":["zip_file"]},
	          "name":"invoice.zip","size":308,
	          "tree":{"node":"root-uuid","root":"root-uuid"}},
	  "request":{"attributes":{"filename":"invoice.zip"},"client":"lazaret","id":"root-uuid"},
	  "scan":{"hash":{"sha256":"aaa"},"entropy":{"entropy":4.76}}}`,

	`{"file":{"depth":1,"flavors":{"mime":["application/x-dosexec"]},
	          "name":"invoice.exe","size":2048,"source":"ScanZip",
	          "tree":{"node":"child-uuid","parent":"root-uuid","root":"root-uuid"}},
	  "request":{"attributes":{"filename":"invoice.zip"},"client":"lazaret"},
	  "scan":{"hash":{"sha256":"bbb"},
	          "yara":{"matches":["Malware_Dropper"],
	                  "meta":[{"rule":"Malware_Dropper","identifier":"author","value":"someone"},
	                          {"rule":"Malware_Dropper","identifier":"severity","value":"high"}],
	                  "tags":["dropper"],"rules_loaded":2},
	          "javascript":{"identifiers":["x","eval","unescape"]}}}`,
}

func TestExplodeReturnsTheWholeTree(t *testing.T) {
	fake := &fakeFrontend{events: archiveEvents}
	c := newFake(t, fake, nil)

	out, err := c.Explode(context.Background(), "invoice.zip", []byte("PK\x03\x04 pretend archive"))
	if err != nil {
		t.Fatalf("Explode: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d records, want 2 (the archive and its member)", len(out))
	}

	// Depth and parentage are what make the flattened list a tree again.
	if got := mdm.Deref(out[0].Depth); got != 0 {
		t.Errorf("first record depth = %d, want 0", got)
	}
	if got := mdm.Deref(out[1].Depth); got != 1 {
		t.Errorf("second record depth = %d, want 1", got)
	}
	if got := mdm.Deref(out[1].ParentNodeID); got != "root-uuid" {
		t.Errorf("parent_node_id = %q, want root-uuid", got)
	}
	if got := mdm.Deref(out[1].FileName); got != "invoice.exe" {
		t.Errorf("file_name = %q", got)
	}

	// The YARA result, at the path MQL reads it from.
	scan := out[1].Scan
	if scan == nil || scan.Yara == nil || len(scan.Yara.Matches) != 1 {
		t.Fatalf("no YARA match on the extracted file: %+v", scan)
	}
	if got := mdm.Deref(scan.Yara.Matches[0].Name); got != "Malware_Dropper" {
		t.Errorf("match name = %q", got)
	}
	if got := scan.Yara.Matches[0].Meta["severity"]; got != "high" {
		t.Errorf("match meta = %v", scan.Yara.Matches[0].Meta)
	}
}

func TestTheWholeFileIsSent(t *testing.T) {
	// Larger than one chunk, so the streaming path is actually exercised.
	payload := []byte(strings.Repeat("abcdefgh", 20_000))

	fake := &fakeFrontend{events: archiveEvents[:1]}
	c := newFake(t, fake, nil)

	if _, err := c.Explode(context.Background(), "big.bin", payload); err != nil {
		t.Fatalf("Explode: %v", err)
	}
	if got := fake.body(); len(got) != len(payload) || string(got) != string(payload) {
		t.Errorf("server received %d bytes, want %d", len(got), len(payload))
	}
	if fake.filename != "big.bin" {
		t.Errorf("filename = %q, want big.bin", fake.filename)
	}
	// The client identifies itself, because an operator reading Strelka's logs should be
	// able to tell where a scan came from.
	if fake.client != "lazaret" {
		t.Errorf("client = %q", fake.client)
	}
}

func TestOversizedFileIsRefusedBeforeSending(t *testing.T) {
	// A bound that only exists on the far side of a network call is a bound you are
	// trusting someone else to keep.
	fake := &fakeFrontend{}
	c := newFake(t, fake, &strelka.Options{MaxFileSize: 1024})

	_, err := c.Explode(context.Background(), "big.bin", make([]byte, 4096))
	if err == nil {
		t.Fatal("an oversized file was sent")
	}
	if len(fake.body()) != 0 {
		t.Error("bytes were streamed before the size check")
	}
}

func TestResultCountIsBounded(t *testing.T) {
	// A zip bomb's purpose is to produce an unbounded number of members. What was
	// collected is still useful, so it is returned rather than discarded.
	var many []string
	for i := range 50 {
		many = append(many, fmt.Sprintf(`{"file":{"name":"f%d","depth":1}}`, i))
	}
	c := newFake(t, &fakeFrontend{events: many}, &strelka.Options{MaxResults: 10})

	out, err := c.Explode(context.Background(), "bomb.zip", []byte("PK"))
	if err != nil {
		t.Fatalf("Explode: %v", err)
	}
	if len(out) != 10 {
		t.Errorf("got %d records, want the limit of 10", len(out))
	}
}

func TestUndecodableRecordIsAnError(t *testing.T) {
	// A record that will not decode means this package has the wire format wrong, and
	// that is a corpus-wide miss rather than one bad file. It used to be skipped, which
	// is how a real mismatch in `scan.yara.matches` survived a green test suite: scans
	// looked healthy while silently returning fewer files than Strelka had found.
	events := []string{
		`{"file":{"name":"good.txt","depth":0}}`,
		`not json at all`,
		``, // Blank events are keepalives, not failures, and stay skipped.
		`{"file":{"name":"alsogood.txt","depth":1}}`,
	}

	c := newFake(t, &fakeFrontend{events: events}, nil)
	if _, err := c.Explode(context.Background(), "x", []byte("data")); err == nil {
		t.Fatal("an undecodable record should fail the scan by default")
	}

	// Availability over fidelity, for callers who choose it explicitly.
	c = newFake(t, &fakeFrontend{events: events}, &strelka.Options{SkipUndecodable: true})
	out, err := c.Explode(context.Background(), "x", []byte("data"))
	if err != nil {
		t.Fatalf("Explode with SkipUndecodable: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d records, want the two decodable ones", len(out))
	}
}

func TestEmptyFileIsNotSent(t *testing.T) {
	fake := &fakeFrontend{}
	c := newFake(t, fake, nil)

	out, err := c.Explode(context.Background(), "empty.txt", nil)
	if err != nil {
		t.Fatalf("Explode: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d records for an empty file", len(out))
	}
	if fake.calls != 0 {
		t.Error("an empty file was still sent to Strelka")
	}
}

func TestServerErrorIsReported(t *testing.T) {
	c := newFake(t, &fakeFrontend{err: errors.New("backend unavailable")}, nil)
	if _, err := c.Explode(context.Background(), "x", []byte("data")); err == nil {
		t.Fatal("a backend failure was not reported")
	}
}

func TestTimeout(t *testing.T) {
	c := newFake(t, &fakeFrontend{delay: 2 * time.Second}, &strelka.Options{Timeout: 100 * time.Millisecond})
	start := time.Now()
	if _, err := c.Explode(context.Background(), "x", []byte("data")); err == nil {
		t.Fatal("a hanging scan returned successfully")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the timeout took %v to fire", elapsed)
	}
}

// ---------------------------------------------------------------------------
// MQL integration
// ---------------------------------------------------------------------------

func messageWithAttachment() *mdm.MessageDataModel {
	return &mdm.MessageDataModel{
		Type: &mdm.MessageType{Inbound: mdm.Ptr(true)},
		Attachments: []*mdm.Attachment{{
			FileName:      mdm.Ptr("invoice.zip"),
			FileExtension: mdm.Ptr("zip"),
			Raw:           []byte("PK\x03\x04 pretend archive"),
		}},
	}
}

func TestCorpusIdiomsEvaluate(t *testing.T) {
	// The shapes real rules use. These are the 178 rules that need nothing but
	// file.explode, so if these do not work the capability has not landed.
	c := newFake(t, &fakeFrontend{events: archiveEvents}, nil)
	enricher := mql.NewMux().Handle(c, strelka.Capabilities()...)
	msg := messageWithAttachment()

	for _, tc := range []struct {
		src  string
		want mql.Verdict
	}{
		{`any(attachments, any(file.explode(.), length(.scan.yara.matches) > 0))`, mql.Match},
		{`any(attachments, any(file.explode(.), any(.scan.yara.matches, .name == "Malware_Dropper")))`, mql.Match},
		{`any(attachments, any(file.explode(.), any(.scan.yara.matches, .meta['severity'] == "high")))`, mql.Match},
		{`any(attachments, any(file.explode(.), any(.scan.yara.matches, .name == "Something_Else")))`, mql.NoMatch},
		// Reaching into an extracted file's own properties.
		{`any(attachments, any(file.explode(.), .file_extension == "exe"))`, mql.Match},
		{`any(attachments, any(file.explode(.), 'unescape' in .scan.javascript.identifiers))`, mql.Match},
		{`any(attachments, any(file.explode(.), 'zip_file' in .flavors.yara))`, mql.Match},
	} {
		t.Run(tc.src, func(t *testing.T) {
			checked, err := mql.Compile(tc.src, nil)
			if err != nil {
				t.Fatalf("compiling: %v", err)
			}
			res := mql.Eval(context.Background(), checked, msg, &mql.EvalOptions{Enricher: enricher})
			if res.Err != nil {
				t.Fatalf("evaluating: %v", res.Err)
			}
			if res.Verdict != tc.want {
				t.Errorf("verdict = %s (missing %v), want %s", res.Verdict, res.Missing, tc.want)
			}
		})
	}
}

func TestExpandArchives(t *testing.T) {
	c := newFake(t, &fakeFrontend{events: archiveEvents}, nil)
	enricher := mql.NewMux().Handle(c, strelka.Capabilities()...)

	checked, err := mql.Compile(`any(attachments, any(file.expand_archives(.).files, .file_name == "invoice.exe"))`, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := mql.Eval(context.Background(), checked, messageWithAttachment(),
		&mql.EvalOptions{Enricher: enricher})
	if res.Err != nil {
		t.Fatalf("evaluating: %v", res.Err)
	}
	if res.Verdict != mql.Match {
		t.Errorf("verdict = %s, want match", res.Verdict)
	}
}

func TestExpandArchivesExcludesTheArchiveItself(t *testing.T) {
	// Depth 0 is the file that was submitted, not something extracted from it.
	c := newFake(t, &fakeFrontend{events: archiveEvents}, nil)
	checked, _ := mql.Compile(`any(attachments, any(file.expand_archives(.).files, .file_name == "invoice.zip"))`, nil)
	res := mql.Eval(context.Background(), checked, messageWithAttachment(),
		&mql.EvalOptions{Enricher: mql.NewMux().Handle(c, strelka.Capabilities()...)})
	if res.Verdict == mql.Match {
		t.Error("the submitted archive was reported as one of its own members")
	}
}

func TestUnreachableStrelkaIsIndeterminate(t *testing.T) {
	// The contract every capability shares: a scan that could not run leaves the rule
	// undecided rather than clearing the message.
	c := newFake(t, &fakeFrontend{err: errors.New("down")}, nil)
	enricher := mql.NewMux().Handle(c, strelka.Capabilities()...)

	checked, _ := mql.Compile(`any(attachments, any(file.explode(.), length(.scan.yara.matches) > 0))`, nil)
	res := mql.Eval(context.Background(), checked, messageWithAttachment(),
		&mql.EvalOptions{Enricher: enricher})

	if res.Err != nil {
		t.Errorf("a failing scan aborted evaluation: %v", res.Err)
	}
	if res.Verdict != mql.Indeterminate {
		t.Errorf("verdict = %s, want indeterminate", res.Verdict)
	}
	if len(res.Missing) != 1 || res.Missing[0] != enrich.CapFileExplode {
		t.Errorf("missing = %v, want [file.explode]", res.Missing)
	}
}

func TestOletoolsIsNotClaimed(t *testing.T) {
	// Strelka runs oletools, but its output is shaped differently from what MQL expects.
	// A lossy mapping would produce rules that look like they work while reading the
	// wrong fields, so the capability is left unanswered.
	c := newFake(t, &fakeFrontend{}, nil)
	_, err := c.Enrich(context.Background(), enrich.CapFileOletools, nil, nil)
	if !mql.IsUnavailable(err) {
		t.Errorf("err = %v, want unavailable", err)
	}
}

func TestConcurrentScans(t *testing.T) {
	// One client serves a whole deployment; gRPC multiplexes the streams.
	c := newFake(t, &fakeFrontend{events: archiveEvents}, nil)

	errs := make(chan error, 8)
	for i := range 8 {
		go func() {
			_, err := c.Explode(context.Background(), fmt.Sprintf("f%d.zip", i), []byte("PK data"))
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Errorf("concurrent scan: %v", err)
		}
	}
}

func TestWireFormatTranslatesToThePublishedShape(t *testing.T) {
	// The seam between what Strelka sends and what rules read. Sublime's published
	// FileExplodeOutput flattens file.* to the top level and renames the tree fields;
	// getting this wrong produces records that decode without error and are empty.
	c := newFake(t, &fakeFrontend{events: archiveEvents}, nil)
	out, err := c.Explode(context.Background(), "invoice.zip", []byte("PK data"))
	if err != nil {
		t.Fatal(err)
	}

	root, child := out[0], out[1]
	for name, got := range map[string]any{
		"root file_name":      mdm.Deref(root.FileName),
		"root file_extension": mdm.Deref(root.FileExtension),
		"root node_id":        mdm.Deref(root.NodeID),
		"child file_name":     mdm.Deref(child.FileName),
		"child source":        mdm.Deref(child.Source),
		"child parent":        mdm.Deref(child.ParentNodeID),
	} {
		if got == "" {
			t.Errorf("%s is empty; the translation dropped it", name)
		}
	}
	if got := mdm.Deref(root.FileExtension); got != "zip" {
		t.Errorf("file_extension = %q, want zip derived from the name", got)
	}
	// flavors.mime is a list on the wire and a single value in the schema.
	if root.Flavors == nil || mdm.Deref(root.Flavors.MIME) != "application/zip" {
		t.Errorf("mime = %+v, want the first entry of the list", root.Flavors)
	}
	if got := mdm.Deref(root.Size); got != 308 {
		t.Errorf("size = %d", got)
	}
	// And the one part that passes straight through.
	if child.Scan == nil || child.Scan.Hash == nil || mdm.Deref(child.Scan.Hash.SHA256) != "bbb" {
		t.Error("the scan tree did not survive")
	}
}
