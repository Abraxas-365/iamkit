// Package signingsvc rotates environment signing keys and serves the
// keyring token issuers and validators read.
package signingsvc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// KeyRequired answers creating a key without IAMKIT_ENCRYPTION_KEY: the
// private key could not be stored sealed.
func KeyRequired() error {
	e := errx.Business("environment signing keys require IAMKIT_ENCRYPTION_KEY to be configured")
	e.Code = "ENCRYPTION_KEY_REQUIRED"
	return e
}

// Service implements signing.Commands, signing.Queries and signing.Keyring.
type Service struct {
	repository signing.Repository
	cipher     signing.Cipher // nil or disabled: environment keys cannot be created
	sealing    func() bool
	deployment *rsa.PrivateKey
	now        func() time.Time
	generate   func() (*rsa.PrivateKey, error)

	mu      sync.Mutex
	cache   *keyring
	loaded  time.Time
	missed  time.Time
	loading chan struct{}
}

// keyring is a snapshot of the published keys.
type keyring struct {
	signers   map[identity.EnvironmentID]signing.Signer
	broken    map[identity.EnvironmentID]error // active keys that do not open
	verifiers map[string]signing.Verifier
	jwks      []signing.JWK
}

var (
	_ signing.Commands = (*Service)(nil)
	_ signing.Queries  = (*Service)(nil)
	_ signing.Keyring  = (*Service)(nil)
)

// New serves the deployment key plus the repository's environment keys.
// sealing reports whether cipher can seal (an encryption key is set).
func New(r signing.Repository, cipher signing.Cipher, sealing func() bool, deployment *rsa.PrivateKey) *Service {
	return &Service{repository: r, cipher: cipher, sealing: sealing, deployment: deployment, now: time.Now,
		generate: func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }}
}

func (s *Service) Create(ctx context.Context, m signing.Mutation) (signing.Key, error) {
	if s.cipher == nil || (s.sealing != nil && !s.sealing()) {
		return signing.Key{}, KeyRequired()
	}
	private, err := s.generate()
	if err != nil {
		return signing.Key{}, errx.Wrap(err, "generate signing key", errx.TypeInternal)
	}
	sealed, err := s.cipher.Seal(x509.MarshalPKCS1PrivateKey(private))
	if err != nil {
		return signing.Key{}, err
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return signing.Key{}, errx.Wrap(err, "encode signing key", errx.TypeInternal)
	}
	id := signing.KeyID(&private.PublicKey)
	m.Action, m.Target = signing.ActionCreate, id
	stored := signing.Stored{Key: signing.Key{ID: id, Environment: m.Environment, Algorithm: signing.Algorithm, State: signing.StateNext}, Sealed: sealed, Public: public}
	if err = s.repository.Create(ctx, m, stored); err != nil {
		return signing.Key{}, err
	}
	s.invalidate()
	return s.Find(ctx, m.Environment, id)
}

func (s *Service) Activate(ctx context.Context, m signing.Mutation, id string) (signing.Key, error) {
	key, err := s.repository.Find(ctx, m.Environment, id)
	if err != nil {
		return signing.Key{}, err
	}
	switch key.State {
	case signing.StateActive:
		return view(key), nil
	case signing.StateRetired:
		return signing.Key{}, errx.Conflict("a retired signing key cannot be activated")
	}
	// Check the key opens before it signs anything.
	if _, err = s.open(key); err != nil {
		return signing.Key{}, err
	}
	m.Action, m.Target = signing.ActionActivate, id
	if err = s.repository.Activate(ctx, m, id, s.now().Add(config.SigningKeyRetireDelay)); err != nil {
		return signing.Key{}, err
	}
	s.invalidate()
	return s.Find(ctx, m.Environment, id)
}

func (s *Service) Retire(ctx context.Context, m signing.Mutation, id string, input signing.Retire) (signing.Key, error) {
	key, err := s.repository.Find(ctx, m.Environment, id)
	if err != nil {
		return signing.Key{}, err
	}
	switch key.State {
	case signing.StateRetired:
		return view(key), nil
	case signing.StateActive:
		return signing.Key{}, signing.ErrKeyInUse("the active signing key cannot be retired; activate another key first")
	case signing.StateRetiring:
		if !input.Force && key.RetireAfter != nil && s.now().Before(*key.RetireAfter) {
			return signing.Key{}, signing.ErrKeyInUse("tokens signed with this key may still be valid until " + key.RetireAfter.UTC().Format(time.RFC3339) + "; pass force to retire it now")
		}
	}
	m.Action, m.Target = signing.ActionRetire, id
	if err = s.repository.Retire(ctx, m, id); err != nil {
		return signing.Key{}, err
	}
	s.invalidate()
	return s.Find(ctx, m.Environment, id)
}

func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[signing.Key], error) {
	stored, err := s.repository.List(ctx, environment, page)
	if err != nil {
		return query.Paginated[signing.Key]{}, err
	}
	out := make([]signing.Key, len(stored.Items))
	for i, key := range stored.Items {
		out[i] = view(key)
	}
	return query.Paginated[signing.Key]{Items: out, Page: stored.Page}, nil
}

func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, id string) (signing.Key, error) {
	key, err := s.repository.Find(ctx, environment, id)
	if err != nil {
		return signing.Key{}, err
	}
	return view(key), nil
}

// view is the operator view of a stored key, with its public JWK while
// the key is published.
func view(key signing.Stored) signing.Key {
	out := key.Key
	if key.State != signing.StateRetired {
		if public, err := parsePublic(key.Public); err == nil {
			jwk := signing.NewJWK(public)
			out.PublicJWK = &jwk
		}
	}
	return out
}

func parsePublic(der []byte) (*rsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errx.Wrap(err, "decode signing key", errx.TypeInternal)
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errx.Internal("signing key is not RSA")
	}
	return public, nil
}

func (s *Service) open(key signing.Stored) (*rsa.PrivateKey, error) {
	if s.cipher == nil {
		return nil, KeyRequired()
	}
	plain, err := s.cipher.Open(key.Sealed)
	if err != nil {
		return nil, err
	}
	private, err := x509.ParsePKCS1PrivateKey(plain)
	if err != nil {
		return nil, errx.Wrap(err, "decode signing key", errx.TypeInternal)
	}
	return private, nil
}

// Signer is the environment's active key, else the deployment key.
func (s *Service) Signer(ctx context.Context, environment identity.EnvironmentID) (signing.Signer, error) {
	ring, err := s.ring(ctx, false)
	if err != nil {
		return signing.Signer{}, err
	}
	if signer, ok := ring.signers[environment]; ok {
		return signer, nil
	}
	// An active key that cannot be opened (the encryption key changed)
	// fails closed rather than silently signing with the deployment key.
	if err := ring.broken[environment]; err != nil {
		return signing.Signer{}, errx.Wrap(err, "environment signing key cannot be opened", errx.TypeInternal)
	}
	return signing.Signer{ID: signing.KeyID(&s.deployment.PublicKey), Private: s.deployment}, nil
}

// Verifier finds a published key; an unknown kid rereads the keys (at
// most once per SigningKeyMissInterval) in case another instance just
// created it.
func (s *Service) Verifier(ctx context.Context, id string) (signing.Verifier, error) {
	deployment := signing.Verifier{ID: signing.KeyID(&s.deployment.PublicKey), Public: &s.deployment.PublicKey}
	if id == "" || id == deployment.ID {
		return deployment, nil
	}
	ring, err := s.ring(ctx, false)
	if err != nil {
		return signing.Verifier{}, err
	}
	if v, ok := ring.verifiers[id]; ok {
		return v, nil
	}
	if ring, err = s.ring(ctx, true); err != nil {
		return signing.Verifier{}, err
	}
	if v, ok := ring.verifiers[id]; ok {
		return v, nil
	}
	return signing.Verifier{}, errx.Unauthorized("unknown signing key")
}

// JWKS lists the deployment key first, then every published environment key.
func (s *Service) JWKS(ctx context.Context) ([]signing.JWK, error) {
	ring, err := s.ring(ctx, false)
	if err != nil {
		return nil, err
	}
	return append([]signing.JWK{signing.NewJWK(&s.deployment.PublicKey)}, ring.jwks...), nil
}

func (s *Service) invalidate() {
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()
}

// ring returns the cached keys, reloading them when stale (or, with miss,
// after an unknown kid, rate limited). One load runs at a time.
func (s *Service) ring(ctx context.Context, miss bool) (*keyring, error) {
	for {
		s.mu.Lock()
		now := s.now()
		fresh := s.cache != nil && now.Sub(s.loaded) < config.SigningKeyCacheTTL
		if fresh && (!miss || now.Sub(s.missed) < config.SigningKeyMissInterval) {
			ring := s.cache
			s.mu.Unlock()
			return ring, nil
		}
		if wait := s.loading; wait != nil {
			s.mu.Unlock()
			select {
			case <-wait:
				miss = false // the load that just finished is fresh enough
				continue
			case <-ctx.Done():
				return nil, errx.Wrap(ctx.Err(), "load signing keys", errx.TypeInternal)
			}
		}
		if miss {
			s.missed = now
		}
		done := make(chan struct{})
		s.loading = done
		s.mu.Unlock()

		ring, err := s.load(ctx)

		s.mu.Lock()
		s.loading = nil
		if err == nil {
			s.cache, s.loaded = ring, now
		}
		s.mu.Unlock()
		close(done)
		if err != nil {
			return nil, err
		}
		return ring, nil
	}
}

func (s *Service) load(ctx context.Context) (*keyring, error) {
	stored, err := s.repository.Published(ctx)
	if err != nil {
		return nil, err
	}
	out := &keyring{signers: map[identity.EnvironmentID]signing.Signer{}, broken: map[identity.EnvironmentID]error{}, verifiers: map[string]signing.Verifier{}}
	for _, key := range stored {
		public, err := parsePublic(key.Public)
		if err != nil {
			return nil, err
		}
		out.verifiers[key.ID] = signing.Verifier{ID: key.ID, Public: public, Environment: key.Environment}
		out.jwks = append(out.jwks, signing.NewJWK(public))
		if key.State == signing.StateActive {
			private, err := s.open(key)
			if err != nil {
				out.broken[key.Environment] = err
				continue
			}
			out.signers[key.Environment] = signing.Signer{ID: key.ID, Private: private}
		}
	}
	return out, nil
}
