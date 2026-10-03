package authsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// exhaustedUsage refuses every limit as reached.
type exhaustedUsage struct{ admitted []string }

func (u *exhaustedUsage) Admit(_ context.Context, _ identity.EnvironmentID, limit string) error {
	u.admitted = append(u.admitted, limit)
	l, _ := usage.Find(limit)
	return usage.ErrExceeded(l, 0)
}
func (u *exhaustedUsage) Count(context.Context, identity.EnvironmentID, string, int64) {}

// Once emails_per_day is reached a code request answers 429 QUOTA_EXCEEDED
// instead of a 202 for an email that never leaves; known and unknown
// addresses get the same answer, and nothing is stored.
func TestCodeEmailsRefusedOverDailyLimit(t *testing.T) {
	for _, raw := range []string{"", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"} {
		var user identity.UserID
		if raw != "" {
			user = identity.MustParseUserID(raw)
		}
		tx := &testTransaction{user: user}
		delivery := &recordingDelivery{}
		s := New(testRepository{tx}, testPasswords{}, testSecrets{}, delivery)
		u := &exhaustedUsage{}
		s.SetUsage(u)
		_, err := s.InitiateChallenge(context.Background(), testBoundary().EnvironmentID, "user@example.com", "login", "")
		if !usage.Exceeded(err) || len(u.admitted) != 1 || u.admitted[0] != usage.LimitEmails {
			t.Fatalf("challenge (user %q): %v admitted=%v", raw, err, u.admitted)
		}
		if len(delivery.got) != 0 || tx.committed {
			t.Fatalf("challenge sent=%d committed=%v", len(delivery.got), tx.committed)
		}
	}

	store := newSignupStore()
	delivery := &recordingDelivery{}
	s := signupService(store, signupPolicy(), delivery)
	s.SetUsage(&exhaustedUsage{})
	if _, err := s.Signup(context.Background(), signupInput()); !usage.Exceeded(err) {
		t.Fatalf("signup: %v", err)
	}
	if len(delivery.got) != 0 || len(store.pending) != 0 {
		t.Fatalf("signup sent=%d pending=%d", len(delivery.got), len(store.pending))
	}
	// An address with an account gets the same refusal.
	store.exists = true
	if _, err := s.Signup(context.Background(), signupInput()); !usage.Exceeded(err) {
		t.Fatalf("signup existing: %v", err)
	}
}
