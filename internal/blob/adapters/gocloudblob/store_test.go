package gocloudblob_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/blob"
	"github.com/Abraxas-365/iamkit/internal/blob/adapters/gocloudblob"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func kind(err error) errx.Type {
	var e *errx.Error
	if errors.As(err, &e) {
		return e.Type
	}
	return ""
}

// contract is what every blob.Store must do.
func contract(t *testing.T, store blob.Store) {
	t.Helper()
	ctx := context.Background()
	key := "logs/2026/03/04/08/stream-1.ndjson.gz"
	body := []byte("hello\nworld\n")
	opts := blob.PutOptions{ContentType: "application/x-ndjson", ContentEncoding: "gzip"}
	if err := store.Put(ctx, key, bytes.NewReader(body), opts); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Never overwrites.
	if err := store.Put(ctx, key, bytes.NewReader([]byte("other")), opts); kind(err) != errx.TypeConflict {
		t.Fatalf("second put: want conflict, got %v", err)
	}
	r, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("get returned %q: the conflicting put overwrote it", got)
	}
	obj, err := store.Stat(ctx, key)
	if err != nil || obj.Size != int64(len(body)) || obj.ContentType != "application/x-ndjson" || obj.ContentEncoding != "gzip" {
		t.Fatalf("stat: %+v %v", obj, err)
	}
	if _, err := store.Stat(ctx, "missing"); kind(err) != errx.TypeNotFound {
		t.Fatalf("stat missing: %v", err)
	}
	if _, err := store.Get(ctx, "missing"); kind(err) != errx.TypeNotFound {
		t.Fatalf("get missing: %v", err)
	}
	if err := store.Put(ctx, "../escape", bytes.NewReader(nil), opts); kind(err) != errx.TypeValidation {
		t.Fatalf("bad key: %v", err)
	}
	if err := store.Put(ctx, "x", bytes.NewReader(nil), blob.PutOptions{}); kind(err) != errx.TypeValidation {
		t.Fatalf("no content type: %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.Delete(ctx, key); kind(err) != errx.TypeNotFound {
		t.Fatalf("delete missing: %v", err)
	}
	if err := store.Put(ctx, key, bytes.NewReader(body), opts); err != nil {
		t.Fatalf("put after delete: %v", err)
	}
}

func TestMemoryContract(t *testing.T) {
	mem := gocloudblob.NewMemory()
	store, err := mem.Open(context.Background(), blob.Target{Bucket: "b"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	contract(t, store)
}

func TestOpenRequiresTarget(t *testing.T) {
	if _, err := (gocloudblob.Opener{}).Open(context.Background(), blob.Target{Bucket: "b"}); kind(err) != errx.TypeValidation {
		t.Fatalf("want validation, got %v", err)
	}
}

// Fixture credentials of the RustFS test server.
const (
	accessKey = "testaccess"
	secretKey = "testsecret123"
	rustfs    = "rustfs/rustfs:1.0.0"
)

func TestS3RustFS(t *testing.T) {
	if os.Getenv("IAMKIT_TEST_E2E") != "1" {
		t.Skip("set IAMKIT_TEST_E2E=1 to run container tests")
	}
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, rustfs,
		testcontainers.WithExposedPorts("9000/tcp"),
		testcontainers.WithEnv(map[string]string{"RUSTFS_ACCESS_KEY": accessKey, "RUSTFS_SECRET_KEY": secretKey}),
		testcontainers.WithWaitStrategyAndDeadline(2*time.Minute, wait.ForHTTP("/health").WithPort("9000/tcp")))
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := c.PortEndpoint(ctx, "9000/tcp", "http")
	if err != nil {
		t.Fatal(err)
	}
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")})
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("iam-logs")}); err != nil {
		t.Fatal(err)
	}
	// The loopback container needs the unguarded transport.
	opener := gocloudblob.Opener{Transport: http.DefaultTransport}
	target := blob.Target{Bucket: "iam-logs", Region: "us-east-1", Endpoint: endpoint, PathStyle: true, AccessKeyID: accessKey, SecretAccessKey: secretKey}
	store, err := opener.Open(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	contract(t, store)

	// Wrong credentials surface on the first write, without echoing them.
	target.SecretAccessKey = "wrong-secret-0000"
	bad, err := opener.Open(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	err = bad.Put(ctx, "denied", bytes.NewReader([]byte("x")), blob.PutOptions{ContentType: "text/plain"})
	if err == nil {
		t.Fatal("wrong credentials must fail")
	}
}
