package authsvc

import (
	"context"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type keyCodec struct {
	authentication.TokenCodec
	key    identity.UserKeyID
	signed authentication.Token
}

func (c *keyCodec) AssertionKey(string) (identity.UserKeyID, error) { return c.key, nil }
func (c *keyCodec) VerifyAssertion(context.Context, string, authentication.MachineKey) (authentication.Assertion, error) {
	return authentication.Assertion{JTI: "j", Expires: time.Now().Add(time.Minute)}, nil
}
func (c *keyCodec) Sign(_ context.Context, t authentication.Token) (string, error) {
	c.signed = t
	return "jwt", nil
}

type keyRepository struct {
	authentication.TokenRepository
	key     authentication.MachineKey
	grant   *authentication.KeyGrant
	expires time.Time
}

func (r *keyRepository) MachineKey(context.Context, identity.UserKeyID) (authentication.MachineKey, error) {
	return r.key, nil
}
func (r *keyRepository) KeySession(_ context.Context, g authentication.KeyGrant, session identity.SessionID, _, expires time.Time) (authentication.KeySession, error) {
	r.grant, r.expires = &g, expires
	return authentication.KeySession{Session: session, Audience: "api", Permissions: []string{"a:read"}, Authenticated: time.Unix(1700000000, 0)}, nil
}

func TestKeyGrant(t *testing.T) {
	environment := identity.NewEnvironmentID()
	key := authentication.MachineKey{ID: identity.NewUserKeyID(), Environment: environment, User: identity.NewUserID(), Expires: time.Now().Add(time.Hour)}
	boundary := authentication.Context{OrganizationID: identity.NewOrganizationID(), ApplicationID: identity.NewApplicationID(), ResourceID: identity.NewResourceID()}

	// Another environment's boundary never reaches the session.
	repo, codec := &keyRepository{key: key}, &keyCodec{key: key.ID}
	elsewhere := boundary
	elsewhere.EnvironmentID = identity.NewEnvironmentID()
	if _, err := NewTokens(repo, codec, nil, nil).KeyGrant(context.Background(), "a", elsewhere); err == nil || repo.grant != nil {
		t.Fatalf("other environment: %v", err)
	}

	// Without an environment the key's is used; the session never outlives the key.
	raw, err := NewTokens(repo, codec, nil, nil).KeyGrant(context.Background(), "a", boundary)
	if err != nil || raw != "jwt" || repo.grant == nil {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
	if repo.grant.Boundary.EnvironmentID != environment || repo.grant.Assertion.JTI != "j" || !repo.expires.Equal(key.Expires) {
		t.Fatalf("grant = %+v expires = %v", repo.grant, repo.expires)
	}
	got := codec.signed
	if got.Purpose != authentication.PurposeApplication || got.Subject != key.User || got.SessionID.IsZero() || got.OrganizationID != boundary.OrganizationID ||
		got.Audience[0] != "api" || len(got.AMR) != 1 || got.AMR[0] != "swk" || got.AuthTime != 1700000000 || got.Permissions[0] != "a:read" {
		t.Fatalf("token = %+v", got)
	}
}
