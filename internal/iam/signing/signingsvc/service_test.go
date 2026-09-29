package signingsvc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// memory is an in-memory signing.Repository; loads counts Published calls.
type memory struct {
	mu     sync.Mutex
	keys   map[string]*signing.Stored
	audit  []string
	loads  int
	failed bool
}

func (r *memory) Create(_ context.Context, m signing.Mutation, key signing.Stored) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key.Environment, key.CreatedAt = m.Environment, time.Now()
	r.keys[key.ID] = &key
	r.audit = append(r.audit, m.Action)
	return nil
}
func (r *memory) Activate(_ context.Context, m signing.Mutation, id string, retireAfter time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range r.keys {
		if k.Environment == m.Environment && k.State == signing.StateActive {
			k.State, k.RetireAfter = signing.StateRetiring, &retireAfter
		}
	}
	r.keys[id].State, r.keys[id].RetireAfter = signing.StateActive, nil
	r.audit = append(r.audit, m.Action)
	return nil
}
func (r *memory) Retire(_ context.Context, m signing.Mutation, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[id].State = signing.StateRetired
	r.audit = append(r.audit, m.Action)
	return nil
}
func (r *memory) List(context.Context, identity.EnvironmentID, query.Pagination) (query.Paginated[signing.Stored], error) {
	return query.Paginated[signing.Stored]{}, nil
}
func (r *memory) Find(_ context.Context, environment identity.EnvironmentID, id string) (signing.Stored, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.keys[id]
	if !ok || k.Environment != environment {
		return signing.Stored{}, errx.NotFound("signing key not found")
	}
	return *k, nil
}
func (r *memory) Published(context.Context) ([]signing.Stored, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loads++
	if r.failed {
		return nil, errx.Internal("down")
	}
	var out []signing.Stored
	for _, k := range r.keys {
		if k.State != signing.StateRetired {
			out = append(out, *k)
		}
	}
	return out, nil
}

// plain is a no-op cipher (the sealer has its own tests).
type plain struct{}

func (plain) Seal(b []byte) (string, error) { return string(b), nil }
func (plain) Open(s string) ([]byte, error) { return []byte(s), nil }
func enabled() bool                         { return true }
func code(err error) string                 { var e *errx.Error; errors.As(err, &e); return e.Code }
func kind(err error) errx.Type              { var e *errx.Error; errors.As(err, &e); return e.Type }
func (r *memory) state(id string) string    { r.mu.Lock(); defer r.mu.Unlock(); return r.keys[id].State }
func has(jwks []signing.JWK, kid string) bool {
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

func TestRotation(t *testing.T) {
	deployment, _ := rsa.GenerateKey(rand.Reader, 2048)
	repo := &memory{keys: map[string]*signing.Stored{}}
	s := New(repo, plain{}, enabled, deployment)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	ctx := context.Background()
	env, other := identity.NewEnvironmentID(), identity.NewEnvironmentID()
	m := signing.Mutation{Environment: env, Actor: "op"}
	deploymentKID := signing.KeyID(&deployment.PublicKey)

	signer, err := s.Signer(ctx, env)
	if err != nil || signer.ID != deploymentKID {
		t.Fatalf("default signer = %s %v", signer.ID, err)
	}

	first, err := s.Create(ctx, m)
	if err != nil || first.State != signing.StateNext || first.PublicJWK == nil || first.PublicJWK.Kid != first.ID {
		t.Fatalf("create = %+v %v", first, err)
	}
	jwks, _ := s.JWKS(ctx)
	if len(jwks) != 2 || jwks[0].Kid != deploymentKID || !has(jwks, first.ID) {
		t.Fatalf("next key not published: %+v", jwks)
	}
	if signer, _ = s.Signer(ctx, env); signer.ID != deploymentKID {
		t.Fatal("a next key signed")
	}

	if _, err = s.Activate(ctx, m, first.ID); err != nil {
		t.Fatal(err)
	}
	if signer, _ = s.Signer(ctx, env); signer.ID != first.ID {
		t.Fatal("active key does not sign")
	}
	if signer, _ = s.Signer(ctx, other); signer.ID != deploymentKID {
		t.Fatal("another environment changed signer")
	}
	if v, err := s.Verifier(ctx, first.ID); err != nil || !v.Allows(env) || v.Allows(other) {
		t.Fatalf("verifier = %+v %v", v, err)
	}
	if _, err = s.Retire(ctx, m, first.ID, signing.Retire{}); code(err) != "KEY_IN_USE" {
		t.Fatalf("retire active = %v", err)
	}

	second, _ := s.Create(ctx, m)
	if _, err = s.Activate(ctx, m, second.ID); err != nil {
		t.Fatal(err)
	}
	if repo.state(first.ID) != signing.StateRetiring {
		t.Fatalf("replaced key = %s", repo.state(first.ID))
	}
	if _, err = s.Verifier(ctx, first.ID); err != nil {
		t.Fatal("retiring key stopped verifying")
	}
	if _, err = s.Retire(ctx, m, first.ID, signing.Retire{}); code(err) != "KEY_IN_USE" {
		t.Fatalf("early retire = %v", err)
	}
	// After the delay it retires without force, and stops verifying.
	clock = clock.Add(time.Hour)
	if k, err := s.Retire(ctx, m, first.ID, signing.Retire{}); err != nil || k.State != signing.StateRetired || k.PublicJWK != nil {
		t.Fatalf("retire = %+v %v", k, err)
	}
	if _, err = s.Verifier(ctx, first.ID); err == nil {
		t.Fatal("retired key verifies")
	}
	if _, err = s.Activate(ctx, m, first.ID); kind(err) != errx.TypeConflict {
		t.Fatalf("activate retired = %v", err)
	}
	// Force retires a key that is still retiring (a compromise).
	third, _ := s.Create(ctx, m)
	s.Activate(ctx, m, third.ID)
	if _, err = s.Retire(ctx, m, second.ID, signing.Retire{Force: true}); err != nil {
		t.Fatal(err)
	}
	// Another environment cannot see or rotate the keys.
	if _, err = s.Activate(ctx, signing.Mutation{Environment: other}, third.ID); kind(err) != errx.TypeNotFound {
		t.Fatalf("cross-environment activate = %v", err)
	}
	want := []string{signing.ActionCreate, signing.ActionActivate, signing.ActionCreate, signing.ActionActivate, signing.ActionRetire, signing.ActionCreate, signing.ActionActivate, signing.ActionRetire}
	if len(repo.audit) != len(want) {
		t.Fatalf("audit = %v", repo.audit)
	}
	for i := range want {
		if repo.audit[i] != want[i] {
			t.Fatalf("audit = %v", repo.audit)
		}
	}
}

func TestCreateNeedsEncryptionKey(t *testing.T) {
	deployment, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, s := range []*Service{
		New(&memory{keys: map[string]*signing.Stored{}}, nil, nil, deployment),
		New(&memory{keys: map[string]*signing.Stored{}}, plain{}, func() bool { return false }, deployment),
	} {
		if _, err := s.Create(context.Background(), signing.Mutation{Environment: identity.NewEnvironmentID()}); code(err) != "ENCRYPTION_KEY_REQUIRED" {
			t.Fatalf("create = %v", err)
		}
	}
}

// Keys created on another instance are found: the cache rereads on an
// unknown kid, at most once per miss interval.
func TestKeyringCache(t *testing.T) {
	deployment, _ := rsa.GenerateKey(rand.Reader, 2048)
	repo := &memory{keys: map[string]*signing.Stored{}}
	reader := New(repo, plain{}, enabled, deployment)
	writer := New(repo, plain{}, enabled, deployment)
	clock := time.Now()
	reader.now = func() time.Time { return clock }
	ctx := context.Background()
	env := identity.NewEnvironmentID()
	if _, err := reader.JWKS(ctx); err != nil {
		t.Fatal(err)
	}
	key, _ := writer.Create(ctx, signing.Mutation{Environment: env})
	loads := repo.loads
	if _, err := reader.Verifier(ctx, key.ID); err != nil {
		t.Fatalf("unknown kid not reloaded: %v", err)
	}
	if repo.loads != loads+1 {
		t.Fatalf("loads = %d", repo.loads-loads)
	}
	// Unknown kids in a burst reload once.
	loads = repo.loads
	for range 5 {
		reader.Verifier(ctx, "nope")
	}
	if repo.loads != loads {
		t.Fatalf("burst loads = %d", repo.loads-loads)
	}
	// Signing keys refresh with the cache TTL.
	writer.Activate(ctx, signing.Mutation{Environment: env}, key.ID)
	if s, _ := reader.Signer(ctx, env); s.ID == key.ID {
		t.Fatal("cache ignored TTL")
	}
	clock = clock.Add(time.Minute)
	if s, _ := reader.Signer(ctx, env); s.ID != key.ID {
		t.Fatal("cache never refreshed")
	}
	// A failing reload errors; the deployment key still verifies.
	repo.failed = true
	clock = clock.Add(time.Minute)
	if _, err := reader.Signer(ctx, env); err == nil {
		t.Fatal("stale signer used after failed reload")
	}
	if _, err := reader.Verifier(ctx, signing.KeyID(&deployment.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

// An active key that cannot be opened never falls back to the deployment key.
func TestBrokenActiveKeyFailsClosed(t *testing.T) {
	deployment, _ := rsa.GenerateKey(rand.Reader, 2048)
	repo := &memory{keys: map[string]*signing.Stored{}}
	s := New(repo, plain{}, enabled, deployment)
	ctx := context.Background()
	env := identity.NewEnvironmentID()
	key, _ := s.Create(ctx, signing.Mutation{Environment: env})
	s.Activate(ctx, signing.Mutation{Environment: env}, key.ID)
	repo.keys[key.ID].Sealed = "garbage"
	s.invalidate()
	if _, err := s.Signer(ctx, env); err == nil {
		t.Fatal("signed with deployment key instead")
	}
	if _, err := s.Signer(ctx, identity.NewEnvironmentID()); err != nil {
		t.Fatal("other environments broken too")
	}
}
