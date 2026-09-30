// SPDX-License-Identifier: AGPL-3.0-only

// Package strelka answers MQL's file.explode by talking to a Strelka deployment.
//
// # Why this is an integration and not an implementation
//
// file.explode is the single highest-leverage capability in the language: 414 rules in
// the public corpus mention it and 178 need nothing else, which is more than any other
// enrichment. It is also the one we do not have to build. Sublime's own platform runs
// [Strelka], Target's file-analysis framework, under Apache-2.0 — their published
// FileExplodeOutput schema is literally Strelka's response object, which is why
// mdm.FileExplodeOutput is generated from it rather than invented.
//
// So this package is a client, not a scanner. It streams a file to a Strelka frontend and
// converts what comes back.
//
// # What explosion actually does
//
// Strelka recursively extracts a file and runs scanners over every layer: an archive
// yields its members, a document yields its embedded objects and macros, an image yields
// its text. Each layer comes back as its own record with depth, node_id and
// parent_node_id, so the result is a tree flattened into a list — which is exactly the
// shape MQL iterates with any(file.explode(.), ...).
//
// This is also where YARA runs in Sublime's model, surfacing at .scan.yara.matches. A
// Strelka deployment with signatures loaded populates that field, and the yara package in
// this repository produces the same shape for attachments scanned without explosion.
//
// # Handling hostile input
//
// Everything sent here is an attachment from an untrusted message, and the whole point of
// the component is to open it. An archive that expands to a terabyte is a known attack,
// not a hypothetical. Strelka enforces its own limits server-side; this client adds its
// own on what it will send and what it will accept back, because a bound that only exists
// on the far side of a network call is a bound you are trusting someone else to keep.
//
// [Strelka]: https://github.com/target/strelka
package strelka

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	pb "github.com/lazaretemail/lazaret/strelka/strelkapb"
)

// DefaultAddress is Strelka's frontend port.
const DefaultAddress = "localhost:57314"

const (
	// DefaultTimeout bounds one scan. Explosion is recursive and a large archive is
	// genuinely slow, so this is generous compared with the other enrichers.
	DefaultTimeout = 60 * time.Second

	// DefaultMaxFileSize caps what will be sent. Strelka has its own limit; this one
	// exists so that a malformed message cannot make us stream a gigabyte across the
	// network before the far side rejects it.
	DefaultMaxFileSize = 64 << 20

	// DefaultMaxResults caps how many extracted files will be accepted from one scan.
	// A zip bomb's whole purpose is to produce an unbounded number of members, and the
	// limit belongs on this side of the connection as well as the far side.
	DefaultMaxResults = 10_000

	// chunkSize is how much file data goes in one stream message.
	chunkSize = 32 << 10
)

// Options configure a Client.
type Options struct {
	// TLS credentials. Nil means an insecure connection, which is appropriate only when
	// Strelka is reached over a private network — it will be handed every attachment
	// that arrives, so the link deserves the same care as the mail itself.
	TLS credentials.TransportCredentials
	// Address of the Strelka frontend. Empty means DefaultAddress.
	Address string
	// ClientName identifies this engine in Strelka's own logs.
	ClientName string
	// DialOptions are passed through, for callers with their own requirements.
	DialOptions []grpc.DialOption
	// Timeout bounds one scan.
	Timeout time.Duration
	// MaxFileSize caps what will be sent.
	MaxFileSize int
	// MaxResults caps how many extracted files one scan may yield.
	MaxResults int
	// Gatekeeper asks Strelka to serve a cached result when it has one. Worth having on:
	// the same attachment reaches many recipients, and re-exploding it each time is pure
	// waste.
	Gatekeeper bool
	// SkipUndecodable keeps a scan going when one of Strelka's records cannot be
	// translated, returning the rest of the tree instead of an error. Off by default:
	// a record that will not decode means this package's understanding of the wire
	// format is wrong, and that has twice been a silent, corpus-wide miss rather than
	// a one-off bad file. Turn it on where availability beats fidelity.
	SkipUndecodable bool
}

func (o *Options) address() string {
	if o.Address != "" {
		return o.Address
	}
	return DefaultAddress
}

func (o *Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultTimeout
}

func (o *Options) maxFileSize() int {
	if o.MaxFileSize > 0 {
		return o.MaxFileSize
	}
	return DefaultMaxFileSize
}

func (o *Options) maxResults() int {
	if o.MaxResults > 0 {
		return o.MaxResults
	}
	return DefaultMaxResults
}

func (o *Options) clientName() string {
	if o.ClientName != "" {
		return o.ClientName
	}
	return "lazaret"
}

// Client talks to a Strelka frontend.
//
// Safe for concurrent use: one client serves a whole deployment, and the underlying gRPC
// connection multiplexes streams.
type Client struct {
	opts Options
	conn *grpc.ClientConn
	api  pb.FrontendClient

	// closeOnce guards Close, which may be called from a shutdown path racing an
	// in-flight scan.
	closeOnce sync.Once
}

// Dial connects to a Strelka frontend.
//
// The connection is lazy, so this succeeds even when Strelka is not yet up; the first
// scan is what reports a problem, and reports it as an unavailable capability rather than
// as a failure to start.
func Dial(opts *Options) (*Client, error) {
	var o Options
	if opts != nil {
		o = *opts
	}

	creds := o.TLS
	if creds == nil {
		creds = insecure.NewCredentials()
	}
	dialOpts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		// Responses are JSON documents per extracted file and can be large for a
		// document with many embedded objects.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64 << 20)),
	}, o.DialOptions...)

	conn, err := grpc.NewClient(o.address(), dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("strelka: connecting to %s: %w", o.address(), err)
	}
	return &Client{opts: o, conn: conn, api: pb.NewFrontendClient(conn)}, nil
}

// NewWithConn wraps an existing connection, for tests and for callers managing their own.
func NewWithConn(conn *grpc.ClientConn, opts *Options) *Client {
	var o Options
	if opts != nil {
		o = *opts
	}
	return &Client{opts: o, conn: conn, api: pb.NewFrontendClient(conn)}
}

// Close releases the connection.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}

// Explode streams a file to Strelka and returns every layer it extracted.
//
// The first element is the file as submitted; the rest are what came out of it, each
// carrying the depth and parent that locate it in the tree.
func (c *Client) Explode(ctx context.Context, filename string, data []byte) ([]*mdm.FileExplodeOutput, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) > c.opts.maxFileSize() {
		return nil, fmt.Errorf("strelka: %s is %d bytes, over the %d-byte limit",
			filename, len(data), c.opts.maxFileSize())
	}

	ctx, cancel := context.WithTimeout(ctx, c.opts.timeout())
	defer cancel()

	stream, err := c.api.ScanFile(ctx)
	if err != nil {
		return nil, fmt.Errorf("strelka: opening a scan: %w", err)
	}

	// Send and receive concurrently. Strelka streams results for inner files while the
	// outer one is still uploading, and a large archive would otherwise fill the flow
	// control window and deadlock.
	type recvResult struct {
		events []*mdm.FileExplodeOutput
		err    error
	}
	done := make(chan recvResult, 1)
	go func() {
		events, err := c.receive(stream)
		done <- recvResult{events, err}
	}()

	sendErr := c.send(stream, filename, data)
	// CloseSend regardless: the receiver must see the end of the stream, and leaving it
	// open on a send failure leaks the goroutine until the context expires.
	if cerr := stream.CloseSend(); sendErr == nil {
		sendErr = cerr
	}

	res := <-done
	if res.err != nil {
		return nil, res.err
	}
	if sendErr != nil {
		return nil, fmt.Errorf("strelka: sending %s: %w", filename, sendErr)
	}
	return res.events, nil
}

func (c *Client) send(stream grpc.BidiStreamingClient[pb.ScanFileRequest, pb.ScanResponse], filename string, data []byte) error {
	// Strelka takes the request metadata on the first message of the stream and the file
	// body across as many as it needs.
	first := &pb.ScanFileRequest{
		Request: &pb.Request{
			Client:     c.opts.clientName(),
			Source:     "lazaret",
			Gatekeeper: c.opts.Gatekeeper,
		},
		Attributes: &pb.Attributes{Filename: filename},
	}

	for offset := 0; offset < len(data); offset += chunkSize {
		end := min(offset+chunkSize, len(data))

		msg := first
		if msg == nil {
			msg = &pb.ScanFileRequest{}
		}
		msg.Data = data[offset:end]
		if err := stream.Send(msg); err != nil {
			// io.EOF from Send means the server closed the stream; the real reason is
			// on the receive side, so it is not wrapped here.
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		first = nil
	}
	return nil
}

func (c *Client) receive(stream grpc.BidiStreamingClient[pb.ScanFileRequest, pb.ScanResponse]) ([]*mdm.FileExplodeOutput, error) {
	var out []*mdm.FileExplodeOutput

	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("strelka: %w", err)
		}
		if strings.TrimSpace(resp.GetEvent()) == "" {
			continue
		}

		// Each event is one extracted file's record. It is translated rather than
		// decoded straight into the model: Strelka's wire format nests the file
		// metadata under `file` and the published schema flattens it. See convert.go.
		//
		// A record that will not decode is a bug in that translation, not bad input,
		// so it fails the scan. This used to `continue`, and that is precisely how a
		// second wire-format mismatch stayed hidden: scans looked healthy while
		// quietly returning fewer files than Strelka had found, and a rule reading an
		// attachment that had been dropped matched nothing with no error to say why.
		// Callers who would rather have a partial tree than none can set
		// SkipUndecodable.
		record, err := decodeEvent([]byte(resp.GetEvent()))
		if err != nil {
			if c.opts.SkipUndecodable {
				continue
			}
			return nil, fmt.Errorf("strelka: decoding a scan result: %w", err)
		}
		out = append(out, record)

		if len(out) >= c.opts.maxResults() {
			// A bomb's whole purpose is to produce an unbounded number of members.
			// What has been collected is still useful, so it is returned rather than
			// discarded, and the truncation is visible in the count.
			return out, nil
		}
	}
}

// ---------------------------------------------------------------------------
// MQL integration
// ---------------------------------------------------------------------------

// Capabilities are what this client can answer, for registering with an mql.MuxEnricher.
//
// beta.ocr, beta.scan_qr and beta.parse_exif are here despite sitting among the ml.*
// functions in the rule text. None of them needs a model: Strelka already runs tesseract,
// zbar and exiftool over every file, so the answers are in the scan this client was
// fetching for file.explode anyway. See scanners.go.
//
// Their reach is narrower than raw corpus counts suggest, and worth stating plainly.
// beta.ocr appears 311 times but 231 of those are `beta.ocr(file.message_screenshot())`,
// which needs module 4; only the ~70 calls on an attachment are answered here. beta.
// parse_exif is the opposite — 90 of its 104 calls are on an attachment. The nested
// fields reached through file.explode matter more than either: `.scan.ocr.raw` alone is
// read by 505 rules, more than any other enrichment field in the corpus.
//
// file.oletools is not answered here, and that is no longer a gap: it is implemented
// in package oletools, locally and in Go.
//
// The reason it is not mapped from Strelka still stands and is worth keeping. Scanning
// a real OLE2 document, Strelka emits counts and child records —
//
//	"ole": {"total": {"extracted": 1, "streams": 1}}
//	"vba": {"total": {"extracted": 0, "files": 0}}
//
// — while what the corpus reads is the OOXML relationship targets that remote template
// injection uses, whether a VBA project auto-executes, and oletools' own risk verdict.
// None of that is on this wire. A mapping would have had to invent
// `indicators.vba_macros.exists` from a stream count and `relationships` from nothing,
// producing rules that appear to work while reading fields nobody populated.
//
// So it was implemented rather than approximated. An Office document is a zip or a
// compound file and the answers are in the bytes, which also means the capability
// needs no service at all — see package oletools.
func Capabilities() []enrich.Capability {
	return []enrich.Capability{
		enrich.CapFileExplode,
		enrich.CapFileExpandArchives,
		enrich.CapBetaOCR,
		enrich.CapBetaScanQR,
		enrich.CapBetaParseExif,
	}
}

// Enrich implements mql.Enricher.
func (c *Client) Enrich(ctx context.Context, cap enrich.Capability, args []mql.Value, kwargs map[string]mql.Value) (mql.Value, error) {
	switch cap {
	case enrich.CapFileExplode:
		return c.enrichExplode(ctx, args)
	case enrich.CapFileExpandArchives:
		return c.enrichExpand(ctx, args)
	case enrich.CapBetaOCR:
		return c.enrichOCR(ctx, args)
	case enrich.CapBetaScanQR:
		return c.enrichScanQR(ctx, args)
	case enrich.CapBetaParseExif:
		return c.enrichParseExif(ctx, args)
	}
	return mql.NullValue, enrich.NotImplemented(cap)
}

func (c *Client) enrichExplode(ctx context.Context, args []mql.Value) (mql.Value, error) {
	filename, data, ok := fileFrom(args)
	if !ok {
		return mql.NullValue, nil
	}

	records, err := c.Explode(ctx, filename, data)
	if err != nil {
		return mql.NullValue, &enrich.Unavailable{
			Capability: enrich.CapFileExplode,
			Reason:     "scan failed",
			Err:        err,
		}
	}

	values := make([]mql.Value, len(records))
	for i, r := range records {
		values[i] = mql.FromGo(r)
	}
	return mql.ArrayValue(values), nil
}

// enrichExpand answers file.expand_archives from the same scan.
//
// Strelka does not separate extraction from scanning, so the archive is exploded and the
// members are reported without their scan results — which is what expand_archives means.
func (c *Client) enrichExpand(ctx context.Context, args []mql.Value) (mql.Value, error) {
	filename, data, ok := fileFrom(args)
	if !ok {
		return mql.NullValue, nil
	}

	records, err := c.Explode(ctx, filename, data)
	if err != nil {
		return mql.NullValue, &enrich.Unavailable{
			Capability: enrich.CapFileExpandArchives,
			Reason:     "scan failed",
			Err:        err,
		}
	}

	out := &mdm.ExpandArchivesResult{}
	for _, r := range records {
		// Depth 0 is the archive itself, not something extracted from it.
		if mdm.Deref(r.Depth) == 0 {
			continue
		}
		file := &mdm.File{FileName: r.FileName, Size: r.Size}
		if r.FileExtension != nil {
			file.FileExtension = r.FileExtension
		}
		out.Files = append(out.Files, file)
	}
	return mql.FromGo(out), nil
}

// fileFrom pulls a filename and bytes out of whatever MQL passed in.
//
// The corpus idiom is `any(attachments, file.explode(.))`, so the argument is usually an
// Attachment; it can also be a File from an earlier explosion, or the message body's
// HTML. Each carries its content under a different field name.
func fileFrom(args []mql.Value) (filename string, data []byte, ok bool) {
	if len(args) == 0 {
		return "", nil, false
	}
	v := args[0]

	for _, field := range []string{"file_name", "name"} {
		if got, k := v.Field(field).AsString(); k && got != "" {
			filename = got
			break
		}
	}
	if filename == "" {
		filename = "attachment"
	}

	// raw holds an attachment's bytes; the body's HTML keeps its content under raw too.
	for _, field := range []string{"raw", "data", "content"} {
		if b, k := v.Field(field).AsBytes(); k && len(b) > 0 {
			return filename, b, true
		}
	}

	// A bare string argument is content in its own right.
	if s, k := v.AsString(); k && s != "" {
		return filename, []byte(s), true
	}
	return "", nil, false
}
