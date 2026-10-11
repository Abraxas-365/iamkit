// Package blob is the port for binary object storage. IAMKit uses it to
// write log stream batches to a customer's bucket. Adapters live in
// blob/adapters; consumers depend only on Store and Opener, so no cloud SDK
// reaches the domain.
//
// Objects are immutable: Put never overwrites. A retried upload of the same
// key is a Conflict the caller may treat as already done.
package blob

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// PutOptions describe the object being written.
type PutOptions struct {
	// ContentType is required, e.g. "application/x-ndjson".
	ContentType string
	// ContentEncoding is optional, e.g. "gzip".
	ContentEncoding string
	// Metadata is optional: small string pairs.
	Metadata map[string]string
}

// Object is the stored object's attributes.
type Object struct {
	Key             string
	ContentType     string
	ContentEncoding string
	Size            int64
	Metadata        map[string]string
}

// Target names one bucket and the credentials to reach it. Unlike a
// deployment-wide store, IAMKit opens a bucket per log stream with the
// customer's own static credentials.
type Target struct {
	Bucket string
	Region string
	// Endpoint is an S3-compatible server's base URL (MinIO, R2, …); empty
	// for AWS S3.
	Endpoint string
	// PathStyle addresses the bucket in the path (many S3-compatible
	// servers need it).
	PathStyle       bool
	AccessKeyID     string
	SecretAccessKey string
}

// ValidateKey rejects keys that could escape their prefix or behave
// differently across backends.
func ValidateKey(key string) error {
	switch {
	case key == "":
		return errx.Validation("blob key is empty")
	case len(key) > 1024:
		return errx.Validation("blob key is too long")
	case strings.HasPrefix(key, "/"), strings.HasSuffix(key, "/"):
		return errx.Validation("blob key must not start or end with '/'")
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errx.Validation("blob key has an empty or relative segment")
		}
	}
	if strings.ContainsAny(key, "\\\x00") {
		return errx.Validation("blob key has invalid characters")
	}
	return nil
}
