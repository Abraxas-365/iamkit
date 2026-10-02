package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunnerRunsJobsUntilCancelled(t *testing.T) {
	var rounds, lagged atomic.Int32
	r := &Runner{}
	r.Add(Job{Name: "count", Interval: 5 * time.Millisecond,
		Run: func(context.Context) (bool, error) {
			// The first round asks for an immediate second one.
			return rounds.Add(1) == 1, nil
		},
		Lag: func(context.Context) (time.Duration, error) { lagged.Add(1); return time.Second, nil },
	})
	if r.State() != StateIdle {
		t.Fatalf("state = %s, want idle", r.State())
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	r.Start(ctx) // idempotent
	if r.State() != StateRunning {
		t.Fatalf("state = %s, want running", r.State())
	}
	deadline := time.Now().Add(2 * time.Second)
	for rounds.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if !r.Wait(time.Second) {
		t.Fatal("jobs did not stop")
	}
	if rounds.Load() < 4 || lagged.Load() < 3 {
		t.Fatalf("rounds = %d, lag reads = %d", rounds.Load(), lagged.Load())
	}
	deadline = time.Now().Add(time.Second)
	for r.State() != StateStopped && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.State() != StateStopped {
		t.Fatalf("state = %s, want stopped", r.State())
	}
}

func TestDisabledRunnerRunsNothing(t *testing.T) {
	r := &Runner{Disabled: true}
	var ran atomic.Bool
	r.Add(Job{Name: "never", Run: func(context.Context) (bool, error) { ran.Store(true); return false, nil }})
	r.Start(t.Context())
	time.Sleep(20 * time.Millisecond)
	if ran.Load() || r.State() != StateDisabled {
		t.Fatalf("ran = %v, state = %s", ran.Load(), r.State())
	}
	if got := r.Jobs(); len(got) != 1 || got[0] != "never" {
		t.Fatalf("jobs = %v", got)
	}
}

func TestRoundRecoversPanicsAndErrors(t *testing.T) {
	_, err := Round(t.Context(), Job{Name: "panics", Run: func(context.Context) (bool, error) { panic("boom") }})
	if err == nil || err.Error() != "panic: boom" {
		t.Fatalf("err = %v", err)
	}
	want := errors.New("down")
	more, err := Round(t.Context(), Job{Name: "fails", Run: func(context.Context) (bool, error) { return true, want }})
	if !errors.Is(err, want) || !more {
		t.Fatalf("more = %v, err = %v", more, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Round(ctx, Job{Name: "stopping", Run: func(ctx context.Context) (bool, error) { return false, ctx.Err() }}); err != nil {
		t.Fatalf("interrupted round err = %v", err)
	}
}
