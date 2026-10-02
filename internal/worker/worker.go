// Package worker runs IAMKit's background jobs inside the server binary.
//
// Jobs coordinate through the database (rows claimed with FOR UPDATE SKIP
// LOCKED), so every replica may run them at once; IAMKIT_WORKERS=false turns
// them off on API-only replicas.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

// Job is one periodic background task.
type Job struct {
	// Name identifies the job in logs and metrics (low cardinality).
	Name string
	// Interval is the pause between rounds that found nothing more to do.
	Interval time.Duration
	// Run does one round. more asks for another round at once (a full
	// batch was processed).
	Run func(ctx context.Context) (more bool, err error)
	// Lag, when set, is read before each round: how long the oldest due
	// item has waited (reported as iamkit.worker.lag).
	Lag func(ctx context.Context) (time.Duration, error)
}

// Runner states reported by State.
const (
	StateDisabled = "disabled"
	StateIdle     = "idle"
	StateRunning  = "running"
	StateStopped  = "stopped"
)

// Runner runs jobs until its context ends.
type Runner struct {
	// Disabled keeps Start from running anything (IAMKIT_WORKERS=false).
	Disabled bool

	mu      sync.Mutex
	jobs    []Job
	state   string
	wg      sync.WaitGroup
	started bool
}

// Add registers a job; jobs added after Start do not run.
func (r *Runner) Add(jobs ...Job) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs = append(r.jobs, jobs...)
}

// Jobs returns the registered job names.
func (r *Runner) Jobs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.jobs))
	for _, j := range r.jobs {
		names = append(names, j.Name)
	}
	return names
}

// Start runs every job in its own goroutine until ctx ends. It is a no-op
// when disabled or already started.
func (r *Runner) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Disabled || r.started {
		return
	}
	r.started = true
	r.state = StateRunning
	for _, job := range r.jobs {
		r.wg.Add(1)
		go func(job Job) {
			defer r.wg.Done()
			loop(ctx, job)
		}(job)
	}
	go func() {
		<-ctx.Done()
		r.wg.Wait()
		r.mu.Lock()
		r.state = StateStopped
		r.mu.Unlock()
	}()
}

// Wait blocks until every job returned after its context ended, or until
// timeout; it reports whether they all stopped.
func (r *Runner) Wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// State is disabled, idle (not started), running or stopped.
func (r *Runner) State() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.Disabled:
		return StateDisabled
	case r.state == "":
		return StateIdle
	}
	return r.state
}

func loop(ctx context.Context, job Job) {
	interval := job.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		for ctx.Err() == nil {
			more, err := Round(ctx, job)
			if err != nil || !more {
				break
			}
		}
		timer.Reset(interval)
	}
}

// Round runs one round of job, recovering panics and recording metrics;
// the lag (oldest due item) is read first, as the wait this round clears.
// Tests call it (or Runner.RunOnce) to drive a job synchronously.
func Round(ctx context.Context, job Job) (more bool, err error) {
	if job.Lag != nil {
		if lag, lagErr := job.Lag(ctx); lagErr == nil {
			telemetry.WorkerLag(ctx, job.Name, lag)
		} else if ctx.Err() == nil {
			slog.WarnContext(ctx, "background job lag", "job", job.Name, "error", lagErr)
		}
	}
	start := time.Now()
	func() {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("panic: %v", p)
			}
		}()
		more, err = job.Run(ctx)
	}()
	if ctx.Err() != nil {
		// Shutting down: an interrupted round is not a failure.
		return false, nil
	}
	result := telemetry.Success
	if err != nil {
		result = telemetry.Failure
		slog.ErrorContext(ctx, "background job failed", "job", job.Name, "error", err)
	}
	telemetry.WorkerRun(ctx, job.Name, result, time.Since(start))
	return more, err
}

// RunOnce runs one round of the named job now, whether or not the runner
// started; false when no such job is registered.
func (r *Runner) RunOnce(ctx context.Context, name string) (found bool, err error) {
	r.mu.Lock()
	var job *Job
	for i := range r.jobs {
		if r.jobs[i].Name == name {
			job = &r.jobs[i]
		}
	}
	r.mu.Unlock()
	if job == nil {
		return false, nil
	}
	_, err = Round(ctx, *job)
	return true, err
}
