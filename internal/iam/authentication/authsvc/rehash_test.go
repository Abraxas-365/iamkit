package authsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var rehashUser = identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")

func TestLoginRehashesStaleHash(t *testing.T) {
	cases := map[string]struct {
		passwords testPasswords
		err       error
		want      []string
	}{
		"stale match":    {passwords: testPasswords{stale: true}, want: []string{"hash→hash"}},
		"current hash":   {passwords: testPasswords{}},
		"wrong password": {passwords: testPasswords{mismatch: true, stale: true}},
		"rehash failure": {passwords: testPasswords{stale: true}, err: errors.New("db down"), want: []string{"hash→hash"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tx := &testTransaction{user: rehashUser, rehashErr: c.err}
			_, err := New(testRepository{tx}, c.passwords, testSecrets{}, nil).Login(context.Background(), testBoundary(), "user@example.com", "password", "")
			if c.passwords.mismatch != (err != nil) {
				t.Fatalf("login error = %v", err)
			}
			if len(tx.rehashed) != len(c.want) || (len(c.want) == 1 && tx.rehashed[0] != c.want[0]) {
				t.Fatalf("rehashed = %v, want %v", tx.rehashed, c.want)
			}
			if tx.newHash != "" {
				t.Fatalf("rehash must not go through SetPassword: %q", tx.newHash)
			}
		})
	}
}

// A sign-in that replaces an expired password sets a new hash anyway.
func TestLoginSkipsRehashWhenPasswordIsReplaced(t *testing.T) {
	policy := authentication.DefaultPasswordPolicy()
	policy.MaxAgeDays = 30
	tx := &testTransaction{user: rehashUser, changed: time.Now().Add(-31 * 24 * time.Hour)}
	s := withPolicy(New(testRepository{tx}, stalePasswords{}, testSecrets{}, nil), policy, nil)
	if _, err := s.Login(context.Background(), testBoundary(), "user@example.com", "password", "a brand new password"); err != nil {
		t.Fatal(err)
	}
	if len(tx.rehashed) != 0 || tx.newHash != "hash:a brand new password" {
		t.Fatalf("rehashed %v, new hash %q", tx.rehashed, tx.newHash)
	}
}

// stalePasswords matches only the current password and calls its hash stale.
type stalePasswords struct{ newPasswords }

func (stalePasswords) Compare(_, password string) (bool, bool) { return password == "password", true }

func TestVerifyPasswordRehashesStaleHash(t *testing.T) {
	for name, c := range map[string]struct {
		passwords testPasswords
		want      int
	}{"stale": {testPasswords{stale: true}, 1}, "current": {testPasswords{}, 0}, "wrong": {testPasswords{mismatch: true, stale: true}, 0}} {
		t.Run(name, func(t *testing.T) {
			tx := &testTransaction{user: rehashUser}
			_, err := New(testRepository{tx}, c.passwords, testSecrets{}, nil).VerifyPassword(context.Background(), testBoundary().EnvironmentID, "user@example.com", "password")
			if c.passwords.mismatch != (err != nil) {
				t.Fatalf("error = %v", err)
			}
			if len(tx.rehashed) != c.want {
				t.Fatalf("rehashed = %v", tx.rehashed)
			}
			if c.want == 1 && !tx.committed {
				t.Fatal("rehash not committed")
			}
		})
	}
}
