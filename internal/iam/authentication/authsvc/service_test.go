package authsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type testRepository struct{ tx *testTransaction }

func (r testRepository) Begin(context.Context) (authentication.Transaction, error) { return r.tx, nil }

type testTransaction struct {
	authentication.Transaction
	lookup                error
	user                  identity.UserID
	committed, rolledBack bool
}

func (t *testTransaction) PasswordUser(context.Context, authentication.Context, string) (identity.UserID, string, error) {
	return t.user, "hash", t.lookup
}
func (t *testTransaction) Refresh(context.Context, authentication.Context, []byte) (authentication.Session, error) {
	return authentication.Session{ID: identity.MustParseSessionID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), User: t.user, Expires: time.Now().Add(time.Hour)}, t.lookup
}
func (t *testTransaction) Challenge(context.Context, identity.ChallengeID, identity.UserID, string) (authentication.Challenge, error) {
	return authentication.Challenge{}, t.lookup
}
func (t *testTransaction) EligibleChallengeUser(context.Context, identity.EnvironmentID, string, string) (identity.UserID, error) {
	return t.user, t.lookup
}
func (t *testTransaction) RecentChallenges(context.Context, identity.UserID, string) (int, error) {
	return 0, nil
}
func (t *testTransaction) CreateChallenge(context.Context, identity.ChallengeID, identity.UserID, string, identity.EnvironmentID, []byte) error {
	return nil
}
func (t *testTransaction) Resolve(context.Context, authentication.Context, identity.UserID) (authentication.Access, error) {
	return authentication.Access{Audience: "api"}, nil
}
func (t *testTransaction) CreateSession(context.Context, authentication.Context, identity.UserID, identity.SessionID, time.Time) error {
	return nil
}
func (t *testTransaction) SaveRefresh(context.Context, []byte, identity.UserID, identity.SessionID, time.Time) error {
	return nil
}
func (t *testTransaction) UseRefresh(context.Context, []byte) error { return nil }
func (t *testTransaction) Commit() error                            { t.committed = true; return nil }
func (t *testTransaction) Rollback() error                          { t.rolledBack = true; return nil }
func (t *testTransaction) RevokeSession(context.Context, identity.SessionID) error { return nil }
func (t *testTransaction) FailChallenge(context.Context, identity.ChallengeID) error { return nil }
func (t *testTransaction) CompleteChallenge(context.Context, identity.ChallengeID, identity.UserID, string, identity.EnvironmentID, string) error {
	return nil
}

type testPasswords struct{}

func (testPasswords) Hash(string) (string, error) { return "hash", nil }
func (testPasswords) Compare(string, string) bool { return true }

type testSecrets struct{}

func (testSecrets) Generate(string) (string, []byte, error) { return "refresh", []byte("hash"), nil }
func (testSecrets) Hash(s string) []byte                    { return []byte(s) }
func (testSecrets) Code() (string, error)                   { return "12345678", nil }

type failedDelivery struct{}

func (failedDelivery) Send(context.Context, string, string, string) error {
	return errx.External("unavailable")
}
func testBoundary() authentication.Context {
	id := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	return authentication.Context{
		EnvironmentID:  identity.MustParseEnvironmentID(id),
		OrganizationID: identity.MustParseOrganizationID(id),
		ApplicationID:  identity.MustParseApplicationID(id),
		ResourceID:     identity.MustParseResourceID(id),
	}
}
func TestLookupFailuresRemainInternal(t *testing.T) {
	failure := errx.Internal("database unavailable")
	for _, op := range []string{"login", "refresh", "challenge"} {
		t.Run(op, func(t *testing.T) {
			tx := &testTransaction{lookup: failure}
			s := New(testRepository{tx}, testPasswords{}, testSecrets{}, nil)
			var err error
			switch op {
			case "login":
				_, err = s.Login(context.Background(), testBoundary(), "user@example.com", "password")
			case "refresh":
				_, err = s.Refresh(context.Background(), testBoundary(), "ik_refresh_test")
			case "challenge":
				_, err = s.VerifyChallenge(context.Background(), testBoundary(), identity.MustParseChallengeID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), "12345678", "login", "")
			}
			if !errors.Is(err, failure) {
				t.Fatalf("lost persistence error: %v", err)
			}
			if tx.committed || !tx.rolledBack {
				t.Fatal("lookup failure must roll back")
			}
		})
	}
}
func TestDeliveryFailureDoesNotRevealEligibility(t *testing.T) {
	for _, raw := range []string{"", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"} {
		var user identity.UserID
		if raw != "" {
			user = identity.MustParseUserID(raw)
		}
		tx := &testTransaction{user: user}
		s := New(testRepository{tx}, testPasswords{}, testSecrets{}, failedDelivery{})
		id, err := s.InitiateChallenge(context.Background(), testBoundary().EnvironmentID, "user@example.com", "login")
		if err != nil || id.IsZero() {
			t.Fatalf("eligibility leaked: %q %v", raw, err)
		}
		if tx.committed || !tx.rolledBack {
			t.Fatal("failed delivery must roll back")
		}
	}
}
func TestIssuedBoundaryIsCanonical(t *testing.T) {
	b := testBoundary()
	for _, op := range []string{"login", "refresh"} {
		user := identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
		tx := &testTransaction{user: user}
		s := New(testRepository{tx}, testPasswords{}, testSecrets{}, nil)
		var out authentication.Issued
		var err error
		if op == "login" {
			out, err = s.Login(context.Background(), b, "user@example.com", "password")
		} else {
			out, err = s.Refresh(context.Background(), b, "ik_refresh_test")
		}
		if err != nil {
			t.Fatal(err)
		}
		if out.Context != testBoundary() {
			t.Fatalf("noncanonical %s: %+v", op, out.Context)
		}
	}
}
