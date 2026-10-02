package usagesvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/iam/usage/adapters/usagememory"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type fakeRepository struct {
	usage.Repository
	stored  usage.Values
	reads   int
	totals  map[string]int64
	daily   int64
	added   []usage.Increment
	failAdd bool
	saved   usage.Values
}

func (f *fakeRepository) Limits(context.Context, identity.EnvironmentID) (usage.Stored, error) {
	f.reads++
	return usage.Stored{Values: f.stored}, nil
}
func (f *fakeRepository) SaveLimits(_ context.Context, _ usage.Mutation, v usage.Values) error {
	f.saved, f.stored = v, v
	return nil
}
func (f *fakeRepository) Total(_ context.Context, _ identity.EnvironmentID, name string) (int64, error) {
	return f.totals[name], nil
}
func (f *fakeRepository) Daily(context.Context, identity.EnvironmentID, string, time.Time) (int64, error) {
	return f.daily, nil
}
func (f *fakeRepository) Add(_ context.Context, in []usage.Increment) error {
	if f.failAdd {
		return errors.New("down")
	}
	f.added = append(f.added, in...)
	return nil
}

type brokenWindow struct{}

func (brokenWindow) Take(context.Context, string, int64, time.Duration) (bool, error) {
	return false, errors.New("redis down")
}

func TestAdmit(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	repo := &fakeRepository{stored: usage.Values{usage.LimitUsers: 2, usage.LimitEmails: 3}, totals: map[string]int64{usage.LimitUsers: 1}}
	s := New(repo, usagememory.New(), usage.Values{usage.LimitUsers: 10, usage.LimitRequests: 2})

	// Unlimited is free; totals compare the count with the tighter limit.
	if err := s.Admit(ctx, env, usage.LimitOrganizations); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit(ctx, env, usage.LimitUsers); err != nil {
		t.Fatal(err)
	}
	repo.totals[usage.LimitUsers] = 2
	if err := s.Admit(ctx, env, usage.LimitUsers); !usage.Exceeded(err) {
		t.Fatalf("users at limit: %v", err)
	}
	// Daily limits add counts not yet flushed.
	repo.daily = 1
	s.Count(ctx, env, usage.MetricEmails, 1)
	if err := s.Admit(ctx, env, usage.LimitEmails); err != nil {
		t.Fatal(err)
	}
	s.Count(ctx, env, usage.MetricEmails, 1)
	if err := s.Admit(ctx, env, usage.LimitEmails); !usage.Exceeded(err) {
		t.Fatalf("emails at limit: %v", err)
	}
	// Per-minute limits take window slots.
	for range 2 {
		if err := s.Admit(ctx, env, usage.LimitRequests); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Admit(ctx, env, usage.LimitRequests); !usage.Exceeded(err) {
		t.Fatalf("requests over limit: %v", err)
	}
	// Effective limits are cached.
	if repo.reads != 1 {
		t.Fatalf("limit reads = %d", repo.reads)
	}
	if err := s.Admit(ctx, env, "nope"); err == nil {
		t.Fatal("unknown limit admitted")
	}
}

func TestAdmitFailsOpen(t *testing.T) {
	s := New(&fakeRepository{}, brokenWindow{}, usage.Values{usage.LimitRequests: 1})
	if err := s.Admit(context.Background(), identity.NewEnvironmentID(), usage.LimitRequests); err != nil {
		t.Fatal(err)
	}
}

func TestSetLimits(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	repo := &fakeRepository{totals: map[string]int64{usage.LimitUsers: 5}}
	s := New(repo, usagememory.New(), usage.Values{usage.LimitUsers: 100})
	if err := s.Admit(ctx, env, usage.LimitUsers); err != nil {
		t.Fatal(err)
	}
	five := int64(5)
	if _, err := s.SetLimits(ctx, usage.Mutation{Environment: env}, usage.Set{usage.LimitUsers: &five}); err == nil {
		t.Fatal("non-owner changed limits")
	}
	if _, err := s.SetLimits(ctx, usage.Mutation{Environment: env, Owner: true}, usage.Set{"nope": nil}); err == nil {
		t.Fatal("unknown limit accepted")
	}
	out, err := s.SetLimits(ctx, usage.Mutation{Environment: env, Owner: true}, usage.Set{usage.LimitUsers: &five, usage.LimitSMS: nil})
	if err != nil {
		t.Fatal(err)
	}
	if out.Effective[usage.LimitUsers] != 5 || out.Deployment[usage.LimitUsers] != 100 || len(repo.saved) != 1 {
		t.Fatalf("limits = %+v saved %v", out, repo.saved)
	}
	// The cache is dropped: the new limit applies at once.
	if err := s.Admit(ctx, env, usage.LimitUsers); !usage.Exceeded(err) {
		t.Fatalf("new limit not applied: %v", err)
	}
}

func TestFlush(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	repo := &fakeRepository{failAdd: true}
	s := New(repo, usagememory.New(), nil)
	s.Count(ctx, env, usage.MetricTokens, 2)
	s.Count(ctx, env, usage.MetricTokens, 3)
	s.Count(ctx, identity.EnvironmentID{}, usage.MetricTokens, 3)
	if err := s.Flush(ctx); err == nil {
		t.Fatal("flush hid the failure")
	}
	s.Count(ctx, env, usage.MetricTokens, 1)
	repo.failAdd = false
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(repo.added) != 1 || repo.added[0].Count != 6 || repo.added[0].Metric != usage.MetricTokens {
		t.Fatalf("added = %+v", repo.added)
	}
	if err := s.Flush(ctx); err != nil || len(repo.added) != 1 {
		t.Fatalf("second flush wrote %+v", repo.added)
	}
}
