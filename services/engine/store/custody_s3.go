// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Custody in object storage.
//
// The held copies of quarantined messages are the only remaining version of mail that
// has been deleted from a mailbox, which makes this the most consequential thing the
// engine writes. A local directory works for one node and is what `-raw ./data/raw`
// gives; anything with two engines, or anything that expects to survive the loss of a
// machine, needs shared storage.
//
// The S3 client here is deliberately *not* the one DuckLake uses. DuckDB reaches the
// blob store through its own httpfs extension for Parquet, which is a different access
// pattern — large sequential files written by a compactor — and coupling custody to it
// would mean a change to the corpus layout could move or expire messages under legal
// hold. These objects are written once, read rarely, and deleted only when someone
// decides to.
type s3Custody struct {
	client *s3.Client
	bucket string
	prefix string
}

// newS3Custody builds a client for a raw path of the form s3://bucket/optional/prefix.
func newS3Custody(ctx context.Context, raw string, o Options) (*s3Custody, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("store: parsing the raw path %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("store: the raw path %q names no bucket", raw)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cmp(o.S3Region, "us-east-1")))
	if err != nil {
		return nil, fmt.Errorf("store: configuring the blob store: %w", err)
	}
	if o.S3AccessKey != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(o.S3AccessKey, o.S3SecretKey, "")
	}

	opts := []func(*s3.Options){}
	if o.S3Endpoint != "" {
		scheme := "http://"
		if o.S3UseSSL {
			scheme = "https://"
		}
		endpoint := o.S3Endpoint
		if !strings.Contains(endpoint, "://") {
			endpoint = scheme + endpoint
		}
		opts = append(opts, func(s *s3.Options) {
			s.BaseEndpoint = aws.String(endpoint)
			// Path style, because Garage and most self-hosted S3 servers are reached
			// by IP or by a single hostname, and virtual-host addressing would put
			// the bucket in a DNS name that does not resolve.
			s.UsePathStyle = true
		})
	}

	c := &s3Custody{
		client: s3.NewFromConfig(cfg, opts...),
		bucket: u.Host,
		prefix: strings.Trim(u.Path, "/"),
	}
	return c, nil
}

func (c *s3Custody) key(tenant, messageID string) string {
	// The same hashing as the filesystem path, and for the same reason: a Message-ID
	// comes from the sender, and one containing "../" or a NUL would otherwise choose
	// its own object key. Hashing also spreads keys across the keyspace, which matters
	// more in object storage than on a filesystem — S3 partitions by key prefix.
	name := custodyName(tenant, messageID)
	parts := []string{}
	if c.prefix != "" {
		parts = append(parts, c.prefix)
	}
	parts = append(parts, name[:2], name[2:4], name+".eml")
	return strings.Join(parts, "/")
}

func (c *s3Custody) put(ctx context.Context, tenant, messageID string, raw []byte) error {
	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.key(tenant, messageID)),
		Body:   strings.NewReader(string(raw)),
		// message/rfc822 rather than octet-stream: these are messages, and anything
		// browsing the bucket should be able to tell.
		ContentType: aws.String("message/rfc822"),
	})
	if err != nil {
		return fmt.Errorf("store: holding %s: %w", messageID, err)
	}
	return nil
}

func (c *s3Custody) get(ctx context.Context, tenant, messageID string) ([]byte, error) {
	out, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.key(tenant, messageID)),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNoRaw
		}
		return nil, fmt.Errorf("store: reading held message %s: %w", messageID, err)
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (c *s3Custody) has(ctx context.Context, tenant, messageID string) bool {
	out, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.key(tenant, messageID)),
	})
	// Only a definite answer counts as held. A network error is not a "yes", and
	// treating it as one would let a quarantine delete a message on the strength of
	// a timeout.
	return err == nil && out.ContentLength != nil && *out.ContentLength > 0
}

func (c *s3Custody) purge(ctx context.Context, tenant, messageID string) error {
	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.key(tenant, messageID)),
	})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("store: purging %s: %w", messageID, err)
	}
	return nil
}

// isNotFound distinguishes "there is no such object" from every other failure.
//
// Worth being careful about: a 403 from a misconfigured policy also means GetObject
// fails, and reporting that as ErrNoRaw would tell the action endpoint the message is
// not held — which turns a permissions problem into a refusal to quarantine, or worse,
// into a release that silently finds nothing.
func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	// HeadObject reports a missing key as a bare 404 with no typed error.
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}

// EnsureCustodyBucket creates the bucket if it is missing.
//
// Called at startup rather than on the first write, so a misconfigured blob store is
// an error while someone is watching, and not the first time a message needs holding.
func (c *s3Custody) ensureBucket(ctx context.Context) error {
	_, err := c.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(c.bucket)})
	if err == nil {
		return nil
	}
	if !isNotFound(err) {
		return fmt.Errorf("store: reaching the custody bucket %q: %w", c.bucket, err)
	}
	if _, err := c.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(c.bucket)}); err != nil {
		return fmt.Errorf("store: creating the custody bucket %q: %w", c.bucket, err)
	}
	return nil
}
