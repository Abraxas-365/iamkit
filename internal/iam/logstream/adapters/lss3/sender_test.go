package lss3_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/blob/adapters/gocloudblob"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lss3"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func outbound(at time.Time) logstream.Outbound {
	return logstream.Outbound{Stream: identity.NewLogStreamID(), Environment: identity.NewEnvironmentID(), Destination: "s3", Batch: 12, At: at,
		Config:  logstream.Config{Bucket: "logs", Region: "us-east-1", Prefix: "iam", AccessKeyID: "ak"},
		Secrets: []string{"sk"},
		Records: []logstream.Record{{Source: "events", At: at, Fields: json.RawMessage(`{"id":1}`)}, {Source: "events", At: at, Fields: json.RawMessage(`{"id":2}`)}}}
}

func TestSendWritesObject(t *testing.T) {
	mem := gocloudblob.NewMemory()
	at := time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC)
	b := outbound(at)
	s := lss3.Sender{Opener: mem}
	if out := s.Send(context.Background(), b); !out.OK() {
		t.Fatalf("outcome %+v", out)
	}
	key := "iam/2026/03/04/09/" + b.Stream.String() + "-12.ndjson.gz"
	obj, err := mem.Store("logs").Stat(context.Background(), key)
	if err != nil || obj.ContentType != "application/x-ndjson" || obj.ContentEncoding != "gzip" {
		t.Fatalf("stat %+v %v", obj, err)
	}
	r, _ := mem.Store("logs").Get(context.Background(), key)
	raw, _ := io.ReadAll(r)
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := io.ReadAll(zr)
	lines := strings.Split(strings.TrimSpace(string(text)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"id":1`) || !strings.Contains(lines[1], `"source":"events"`) {
		t.Fatalf("ndjson %q", text)
	}
	// A retry of the same batch finds the object and counts as delivered.
	if out := s.Send(context.Background(), b); !out.OK() {
		t.Fatalf("retry outcome %+v", out)
	}
}

func TestOpenFailure(t *testing.T) {
	mem := gocloudblob.NewMemory()
	mem.Fail = errors.New("boom at https://secret.example.com")
	out := lss3.Sender{Opener: mem}.Send(context.Background(), outbound(time.Now()))
	if out.OK() || strings.Contains(out.Error, "secret.example.com") {
		t.Fatalf("outcome %+v", out)
	}
}
