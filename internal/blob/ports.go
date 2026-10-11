package blob

import (
	"context"
	"io"
)

// Store is implemented by every storage backend (S3 and compatibles,
// memory).
//
// Errors are *errx.Error: NotFound when the key doesn't exist, Conflict when
// Put targets an existing key, Validation for a malformed key.
type Store interface {
	// Put stores r under key. It fails with Conflict if key already exists.
	Put(ctx context.Context, key string, r io.Reader, opts PutOptions) error
	// Get opens the object for reading; the caller must Close it.
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	// Stat returns the object's attributes without reading it.
	Stat(ctx context.Context, key string) (Object, error)
	// Delete removes the object. Deleting a missing key returns NotFound.
	Delete(ctx context.Context, key string) error
	// Close releases the store.
	Close() error
}

// Opener opens the store a Target names. Opening does no network call: a
// wrong bucket or credential surfaces on the first Put.
type Opener interface {
	Open(ctx context.Context, target Target) (Store, error)
}
