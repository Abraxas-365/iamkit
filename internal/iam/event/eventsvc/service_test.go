package eventsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type pruneCall struct {
	environment identity.EnvironmentID
	class       string
	cutoff      time.Time
}

type fakeRepository struct {
	event.Repository
	environments []event.EnvironmentPolicy
	calls        []pruneCall
	full         map[string]bool
}

func (f *fakeRepository) Environments(context.Context) ([]event.EnvironmentPolicy, error) {
	return f.environments, nil
}
func (f *fakeRepository) Prune(_ context.Context, e identity.EnvironmentID, class string, cutoff time.Time, batch int) (int, error) {
	f.calls = append(f.calls, pruneCall{e, class, cutoff})
	if f.full[class] {
		return batch, nil
	}
	return 3, nil
}

type fakeRetention struct {
	stored event.RetentionPolicy
	saved  *event.RetentionPolicy
}

func (f *fakeRetention) Policy(context.Context, identity.EnvironmentID) (event.RetentionPolicy, error) {
	return f.stored, nil
}
func (f *fakeRetention) SavePolicy(_ context.Context, _ event.Mutation, p event.RetentionPolicy) error {
	f.saved, f.stored = &p, p
	return nil
}

var ceilings = event.Ceilings{Security: 365 * 24 * time.Hour, Default: 90 * 24 * time.Hour}

func days(n int) *int64 { v := int64(n) * 86400; return &v }

func TestPruneUsesEffectiveCutoffPerEnvironmentAndClass(t *testing.T) {
	a, b := identity.NewEnvironmentID(), identity.NewEnvironmentID()
	repo := &fakeRepository{environments: []event.EnvironmentPolicy{
		{Environment: a},
		{Environment: b, Policy: event.RetentionPolicy{SecuritySeconds: days(30), DefaultSeconds: days(500)}},
	}}
	s := New(repo, &fakeRetention{}, ceilings)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	more, err := s.Prune(context.Background())
	if err != nil || more {
		t.Fatalf("more=%v err=%v", more, err)
	}
	want := []pruneCall{
		{a, event.ClassSecurity, now.Add(-365 * 24 * time.Hour)},
		{a, event.ClassDefault, now.Add(-90 * 24 * time.Hour)},
		{b, event.ClassSecurity, now.Add(-30 * 24 * time.Hour)},
		// 500 days is above the 90-day ceiling: the ceiling rules.
		{b, event.ClassDefault, now.Add(-90 * 24 * time.Hour)},
	}
	if len(repo.calls) != len(want) {
		t.Fatalf("calls = %+v", repo.calls)
	}
	for i, w := range want {
		if repo.calls[i] != w {
			t.Errorf("call %d = %+v, want %+v", i, repo.calls[i], w)
		}
	}
}

func TestPruneAsksForAnotherRoundOnAFullBatch(t *testing.T) {
	repo := &fakeRepository{environments: []event.EnvironmentPolicy{{Environment: identity.NewEnvironmentID()}}, full: map[string]bool{event.ClassDefault: true}}
	more, err := New(repo, &fakeRetention{}, ceilings).Prune(context.Background())
	if err != nil || !more {
		t.Fatalf("more=%v err=%v", more, err)
	}
}

func TestSetRetention(t *testing.T) {
	env := identity.NewEnvironmentID()
	store := &fakeRetention{}
	s := New(&fakeRepository{}, store, ceilings)
	owner := event.Mutation{Environment: env, Owner: true}

	if _, err := s.SetRetention(context.Background(), event.Mutation{Environment: env}, event.RetentionPolicy{}); err == nil {
		t.Fatal("a non-owner changed the retention")
	}
	if _, err := s.SetRetention(context.Background(), owner, event.RetentionPolicy{DefaultSeconds: days(91)}); err == nil || store.saved != nil {
		t.Fatalf("above the ceiling accepted: %v", err)
	} else {
		var e *errx.Error
		if !errors.As(err, &e) || e.HTTPStatus != 422 {
			t.Fatalf("error = %v", err)
		}
	}
	out, err := s.SetRetention(context.Background(), owner, event.RetentionPolicy{SecuritySeconds: days(30)})
	if err != nil || store.saved == nil {
		t.Fatalf("err = %v", err)
	}
	if *out.SecuritySeconds != 30*86400 || out.DefaultSeconds != nil || out.Effective.Default != int64(ceilings.Default.Seconds()) {
		t.Fatalf("out = %+v", out)
	}
	got, _ := s.Retention(context.Background(), env)
	if got.Effective.Security != 30*86400 || got.Ceilings.Security != int64(ceilings.Security.Seconds()) {
		t.Fatalf("got = %+v", got)
	}
}
