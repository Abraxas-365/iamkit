package oauthsvc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type fakeOutbox struct {
	mu        sync.Mutex
	due       []oauth.LogoutNotification
	delivered []int64
	retried   map[int64]time.Duration
	failed    map[int64]oauth.Mutation
}

func (f *fakeOutbox) ClaimLogouts(_ context.Context, limit int, _ time.Duration) ([]oauth.LogoutNotification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := min(limit, len(f.due))
	out := f.due[:n]
	f.due = f.due[n:]
	return out, nil
}
func (f *fakeOutbox) LogoutDelivered(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered = append(f.delivered, id)
	return nil
}
func (f *fakeOutbox) LogoutRetry(_ context.Context, id int64, wait time.Duration, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retried[id] = wait
	return nil
}
func (f *fakeOutbox) LogoutFailed(_ context.Context, m oauth.Mutation, id int64, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed[id] = m
	return nil
}
func (f *fakeOutbox) RetryLogout(context.Context, oauth.Mutation, int64) error { return nil }
func (f *fakeOutbox) PruneLogouts(context.Context, time.Duration) error        { return nil }
func (f *fakeOutbox) LogoutLag(context.Context) (time.Duration, error)         { return 0, nil }
func (f *fakeOutbox) LogoutDeliveries(context.Context, identity.EnvironmentID, oauth.LogoutFilter, query.Pagination) (query.Paginated[oauth.LogoutDelivery], error) {
	return query.Paginated[oauth.LogoutDelivery]{}, nil
}

type fakeSender map[int64]error

func (f fakeSender) Send(_ context.Context, n oauth.LogoutNotification) error { return f[n.ID] }

func TestDispatchLogouts(t *testing.T) {
	env, client, user := identity.NewEnvironmentID(), identity.NewClientID(), identity.NewUserID()
	note := func(id int64, attempts int, uri string) oauth.LogoutNotification {
		return oauth.LogoutNotification{ID: id, Environment: env, Client: client, Session: identity.NewSessionID(), Subject: user, Attempts: attempts, URI: uri}
	}
	box := &fakeOutbox{retried: map[int64]time.Duration{}, failed: map[int64]oauth.Mutation{}, due: []oauth.LogoutNotification{
		note(1, 1, "https://rp.example/bc"),                       // delivered
		note(2, 1, "https://rp.example/bc"),                       // fails, retried
		note(3, oauth.LogoutMaxAttempts, "https://rp.example/bc"), // fails, given up
		note(4, 1, ""), // URI removed: given up at once
	}}
	down := errors.New("connection refused")
	l := NewLogouts(box, fakeSender{2: down, 3: down})
	n, err := l.DispatchLogouts(context.Background())
	if err != nil || n != 4 {
		t.Fatalf("dispatch = %d %v", n, err)
	}
	if len(box.delivered) != 1 || box.delivered[0] != 1 {
		t.Fatalf("delivered = %v", box.delivered)
	}
	if len(box.retried) != 1 || box.retried[2] != oauth.LogoutRetryBase {
		t.Fatalf("retried = %v", box.retried)
	}
	if len(box.failed) != 2 {
		t.Fatalf("failed = %v", box.failed)
	}
	for _, id := range []int64{3, 4} {
		m := box.failed[id]
		if m.Action != oauth.ActionBackchannelFailed || m.Environment != env || m.Actor != user.String() || m.Target != client.String() {
			t.Fatalf("give-up audit %d = %+v", id, m)
		}
	}
	if n, _ = l.DispatchLogouts(context.Background()); n != 0 {
		t.Fatalf("second round = %d", n)
	}
	if _, err = l.LogoutDeliveries(context.Background(), env, oauth.LogoutFilter{Status: "bogus"}, query.Pagination{}); err == nil {
		t.Fatal("bad filter accepted")
	}
}
