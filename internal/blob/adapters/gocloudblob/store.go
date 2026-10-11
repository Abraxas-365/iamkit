// Package gocloudblob implements blob.Store and blob.Opener on top of
// gocloud.dev/blob: s3blob over aws-sdk-go-v2 for AWS S3 and S3-compatible
// servers (MinIO, R2, RustFS), memblob for tests.
//
// A bucket is opened per Target with the customer's static credentials. The
// HTTP client dials through a transport that is guarded (public addresses
// only) unless a test or IAMKIT_ALLOW_PRIVATE_DELIVERY replaces it.
package gocloudblob

import (
	"context"
	"io"
	"net/http"
	"sync"

	"github.com/Abraxas-365/iamkit/internal/blob"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	gcblob "gocloud.dev/blob"
	"gocloud.dev/blob/memblob"
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcerrors"
)

// Store adapts a gocloud bucket to blob.Store.
type Store struct {
	bucket *gcblob.Bucket
	// shared buckets (Memory) outlive the Store.
	shared bool
}

var _ blob.Store = (*Store)(nil)

// Opener opens S3 buckets. A nil Transport uses netx.Guarded.
type Opener struct {
	Transport http.RoundTripper
}

var _ blob.Opener = Opener{}

// Open builds an S3 client for the target. It makes no request.
func (o Opener) Open(ctx context.Context, target blob.Target) (blob.Store, error) {
	if target.Bucket == "" || target.Region == "" || target.AccessKeyID == "" || target.SecretAccessKey == "" {
		return nil, errx.Validation("bucket, region and credentials are required")
	}
	transport := o.Transport
	if transport == nil {
		transport = netx.Guarded()
	}
	opts := s3.Options{
		Region:      target.Region,
		Credentials: credentials.NewStaticCredentialsProvider(target.AccessKeyID, target.SecretAccessKey, ""),
		HTTPClient: &http.Client{Transport: telemetry.Transport(netx.CapErrors(transport)), Timeout: config.LogStreamTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		UsePathStyle: target.PathStyle,
		// Delivery retries live in the log stream worker.
		RetryMaxAttempts: 1,
		// S3-compatible servers often reject the SDK's default trailing
		// checksums; compute them only where S3 requires them.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	if target.Endpoint != "" {
		opts.BaseEndpoint = aws.String(target.Endpoint)
	}
	bucket, err := s3blob.OpenBucket(ctx, s3.New(opts), target.Bucket, nil)
	if err != nil {
		return nil, errx.Wrap(err, "open blob bucket", errx.TypeInternal)
	}
	return &Store{bucket: bucket}, nil
}

// Memory is an in-memory Opener for tests: every Target.Bucket is one
// shared memblob bucket, so a test can read what a stream wrote.
type Memory struct {
	mu      sync.Mutex
	buckets map[string]*gcblob.Bucket
	// Fail, when set, makes Open fail with it.
	Fail error
}

var _ blob.Opener = (*Memory)(nil)

func NewMemory() *Memory { return &Memory{buckets: map[string]*gcblob.Bucket{}} }

func (m *Memory) Open(_ context.Context, target blob.Target) (blob.Store, error) {
	if m.Fail != nil {
		return nil, m.Fail
	}
	return &Store{bucket: m.bucket(target.Bucket), shared: true}, nil
}

func (m *Memory) bucket(name string) *gcblob.Bucket {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[name]
	if !ok {
		b = memblob.OpenBucket(nil)
		m.buckets[name] = b
	}
	return b
}

// Store returns the shared store of a bucket (never closes it).
func (m *Memory) Store(bucket string) blob.Store { return &Store{bucket: m.bucket(bucket)} }

// Close releases the bucket. The in-memory buckets of Memory stay open for
// the test's lifetime.
func (s *Store) Close() error {
	if s.shared {
		return nil
	}
	return s.bucket.Close()
}

func (s *Store) Put(ctx context.Context, key string, r io.Reader, opts blob.PutOptions) error {
	if err := blob.ValidateKey(key); err != nil {
		return err
	}
	if opts.ContentType == "" {
		return errx.Validation("blob content type is required")
	}
	// The write runs under its own cancelable context: canceling it before
	// Close aborts the upload, so a failed copy never leaves a partial object.
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w, err := s.bucket.NewWriter(wctx, key, &gcblob.WriterOptions{
		ContentType:     opts.ContentType,
		ContentEncoding: opts.ContentEncoding,
		Metadata:        opts.Metadata,
		IfNotExist:      true,
	})
	if err != nil {
		return failure(err, "write blob")
	}
	if _, err := io.Copy(w, r); err != nil {
		cancel()
		_ = w.Close()
		return errx.Wrap(err, "write blob", errx.TypeInternal)
	}
	if err := w.Close(); err != nil {
		return failure(err, "write blob")
	}
	return nil
}

func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := blob.ValidateKey(key); err != nil {
		return nil, err
	}
	r, err := s.bucket.NewReader(ctx, key, nil)
	if err != nil {
		return nil, failure(err, "read blob")
	}
	return r, nil
}

func (s *Store) Stat(ctx context.Context, key string) (blob.Object, error) {
	if err := blob.ValidateKey(key); err != nil {
		return blob.Object{}, err
	}
	a, err := s.bucket.Attributes(ctx, key)
	if err != nil {
		return blob.Object{}, failure(err, "stat blob")
	}
	return blob.Object{Key: key, ContentType: a.ContentType, ContentEncoding: a.ContentEncoding, Size: a.Size, Metadata: a.Metadata}, nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	if err := blob.ValidateKey(key); err != nil {
		return err
	}
	if err := s.bucket.Delete(ctx, key); err != nil {
		return failure(err, "delete blob")
	}
	return nil
}

// failure maps gocloud error codes to errx; driver errors never escape raw
// (they may carry endpoints).
func failure(err error, op string) error {
	switch gcerrors.Code(err) {
	case gcerrors.NotFound:
		return errx.NotFound("blob not found")
	case gcerrors.AlreadyExists, gcerrors.FailedPrecondition:
		return errx.Conflict("blob already exists")
	case gcerrors.InvalidArgument:
		return errx.Wrap(err, op+": invalid argument", errx.TypeValidation)
	case gcerrors.PermissionDenied:
		return errx.Wrap(err, op+": permission denied by storage backend", errx.TypeExternal)
	case gcerrors.Canceled, gcerrors.DeadlineExceeded:
		return errx.Wrap(err, op+": canceled", errx.TypeExternal)
	default:
		return errx.Wrap(err, op, errx.TypeExternal)
	}
}
