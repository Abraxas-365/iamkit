package authsvc

import (
	"context"
	"errors"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Every credential failure must produce the exact same error, otherwise the
// response distinguishes "no such account" from "wrong password" (enumeration).
func TestLoginCredentialFailuresAreIndistinguishable(t *testing.T) {
	user := identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	cases := map[string]struct {
		tx        *testTransaction
		passwords testPasswords
		email     string
	}{
		"unknown email":  {tx: &testTransaction{lookup: errx.Unauthorized("no such user")}, email: "user@example.com"},
		"wrong password": {tx: &testTransaction{user: user}, passwords: testPasswords{mismatch: true}, email: "user@example.com"},
		"no access":      {tx: &testTransaction{user: user, resolve: errx.Unauthorized("no grant")}, email: "user@example.com"},
		"malformed":      {tx: &testTransaction{user: user}, email: "not-an-email"},
	}
	var want string
	for name, c := range cases {
		s := New(testRepository{c.tx}, c.passwords, testSecrets{}, nil)
		_, err := s.Login(context.Background(), testBoundary(), c.email, "password")
		var e *errx.Error
		if !errors.As(err, &e) || e.Type != errx.TypeAuthorization {
			t.Fatalf("%s: want authorization error, got %v", name, err)
		}
		if want == "" {
			want = e.Message
		}
		if e.Message != want {
			t.Errorf("%s: message %q differs from %q", name, e.Message, want)
		}
		if c.tx.committed {
			t.Errorf("%s: failed login committed", name)
		}
	}
}

func TestLoginPassesThroughInternalResolveErrors(t *testing.T) {
	failure := errx.Internal("database unavailable")
	tx := &testTransaction{user: identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), resolve: failure}
	s := New(testRepository{tx}, testPasswords{}, testSecrets{}, nil)
	if _, err := s.Login(context.Background(), testBoundary(), "user@example.com", "password"); !errors.Is(err, failure) {
		t.Fatalf("lost internal error: %v", err)
	}
}

type memberRepository struct {
	authentication.TokenRepository
	added []identity.UserID
}

func (r *memberRepository) AddMember(_ context.Context, _ authentication.Token, user identity.UserID) error {
	r.added = append(r.added, user)
	return nil
}

func TestAddMember(t *testing.T) {
	org := identity.MustParseOrganizationID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	target := identity.MustParseUserID("bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	app := authentication.Token{Purpose: "application", Access: identity.Access{OrganizationID: org}}
	cases := []struct {
		name  string
		token authentication.Token
		user  identity.UserID
		want  int
	}{
		{"not an application token", authentication.Token{Purpose: "management", Access: identity.Access{OrganizationID: org}}, target, 403},
		{"token without organization", authentication.Token{Purpose: "application"}, target, 403},
		{"missing user", app, identity.UserID{}, 400},
		{"ok", app, target, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := &memberRepository{}
			err := NewTokens(repo, nil, nil, nil).AddMember(context.Background(), c.token, c.user)
			if c.want == 0 {
				if err != nil || len(repo.added) != 1 || repo.added[0] != target {
					t.Fatalf("err=%v added=%v", err, repo.added)
				}
				return
			}
			var e *errx.Error
			if !errors.As(err, &e) || e.HTTPStatus != c.want {
				t.Fatalf("want %d, got %v", c.want, err)
			}
			if len(repo.added) != 0 {
				t.Fatal("repository called on rejected request")
			}
		})
	}
}
