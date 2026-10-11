// Package lss3 writes log stream batches as gzip-compressed NDJSON objects
// to a customer's S3 (or S3-compatible) bucket through the blob port:
//
//	<prefix>/<yyyy>/<mm>/<dd>/<HH>/<stream>-<batch>.ndjson.gz
//
// Objects are never overwritten; a retried batch finds its object already
// there (Conflict) and counts as delivered.
package lss3

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/blob"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
)

// Sender writes batches; Opener builds the bucket's store per delivery.
type Sender struct {
	Opener blob.Opener
}

var _ logstream.Sender = Sender{}

// Object is the batch's NDJSON, gzip-compressed.
func Object(payloads [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	for _, p := range payloads {
		if _, err := zw.Write(append(append([]byte{}, p...), '\n')); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s Sender) Send(ctx context.Context, b logstream.Outbound) logstream.Outcome {
	if len(b.Secrets) == 0 {
		return logstream.OutcomeOf(0, "the secret access key is missing")
	}
	payloads := b.Payloads()
	raw := make([][]byte, len(payloads))
	for i, p := range payloads {
		raw[i] = p
	}
	object, err := Object(raw)
	if err != nil {
		return logstream.OutcomeOf(0, "encode batch")
	}
	at := b.At
	if len(b.Records) > 0 && !b.Records[0].At.IsZero() {
		at = b.Records[0].At
	}
	key := logstream.ObjectKey(b.Config.Prefix, b.Stream, b.Batch, at)
	if b.Test {
		key = logstream.TestObjectKey(b.Config.Prefix, b.Stream, b.At)
	}
	ctx, cancel := context.WithTimeout(ctx, config.LogStreamTimeout)
	defer cancel()
	store, err := s.Opener.Open(ctx, blob.Target{Bucket: b.Config.Bucket, Region: b.Config.Region, Endpoint: b.Config.Endpoint,
		PathStyle: b.Config.PathStyle, AccessKeyID: b.Config.AccessKeyID, SecretAccessKey: b.Secrets[0]})
	if err != nil {
		return logstream.OutcomeOf(0, "cannot open the bucket")
	}
	defer store.Close()
	err = store.Put(ctx, key, bytes.NewReader(object), blob.PutOptions{
		ContentType: logstream.ObjectContentType, ContentEncoding: logstream.ObjectEncoding})
	var e *errx.Error
	switch {
	case err == nil:
		return logstream.Outcome{}
	case errors.As(err, &e) && e.Type == errx.TypeConflict:
		// An earlier attempt stored this batch (the answer was lost).
		return logstream.Outcome{}
	case ctx.Err() != nil:
		return logstream.OutcomeOf(0, "timed out")
	case errors.As(err, &e) && e.Type == errx.TypeExternal && e.Err != nil:
		return logstream.OutcomeOf(0, "the bucket refused the upload: "+classify(e.Err))
	}
	return logstream.OutcomeOf(0, "the bucket refused the upload")
}

// classify names the S3 error code without echoing endpoints or keys.
func classify(err error) string {
	var coded interface{ ErrorCode() string }
	if errors.As(err, &coded) {
		return coded.ErrorCode()
	}
	return "storage error"
}
