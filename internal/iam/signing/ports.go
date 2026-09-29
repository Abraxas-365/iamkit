package signing

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Commands rotate an environment's signing keys; every change is audited.
type Commands interface {
	// Create generates a next key, published in the JWKS at once.
	Create(ctx context.Context, m Mutation) (Key, error)
	// Activate makes a next (or retiring) key sign the environment's
	// tokens; the key it replaces becomes retiring.
	Activate(ctx context.Context, m Mutation, key string) (Key, error)
	// Retire unpublishes a next or retiring key.
	Retire(ctx context.Context, m Mutation, key string, input Retire) (Key, error)
}

// Queries read an environment's signing keys.
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Key], error)
	Find(ctx context.Context, environment identity.EnvironmentID, key string) (Key, error)
}

// Keyring is what token issuers and validators use: the key to sign an
// environment's tokens with, the key a kid names, and the JWKS.
type Keyring interface {
	Signer(ctx context.Context, environment identity.EnvironmentID) (Signer, error)
	// Verifier finds a published key by kid; an empty kid is the
	// deployment key (tokens always carried a kid, but stay lenient).
	Verifier(ctx context.Context, key string) (Verifier, error)
	JWKS(ctx context.Context) ([]JWK, error)
}

// Repository stores environment keys (private key sealed).
type Repository interface {
	// Create, Activate and Retire audit m in the same transaction.
	Create(ctx context.Context, m Mutation, key Stored) error
	// Activate marks key active and the environment's active key (if any)
	// retiring until retireAfter.
	Activate(ctx context.Context, m Mutation, key string, retireAfter time.Time) error
	Retire(ctx context.Context, m Mutation, key string) error
	List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Stored], error)
	Find(ctx context.Context, environment identity.EnvironmentID, key string) (Stored, error)
	// Published lists every key not retired, across environments.
	Published(ctx context.Context) ([]Stored, error)
}

// Cipher seals private keys at rest (IAMKIT_ENCRYPTION_KEY).
type Cipher interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}
