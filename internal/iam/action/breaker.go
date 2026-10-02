package action

import (
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Breaker opens a target's circuit after config.ActionBreakerFailures
// consecutive failures: its calls are skipped for config.ActionBreakerOpen,
// then one call is let through (half open). State is per replica.
type Breaker struct {
	mu    sync.Mutex
	state map[identity.TargetID]*circuit
}

type circuit struct {
	failures int
	openTill time.Time
}

// Allow reports whether a call to target may go out at now.
func (b *Breaker) Allow(target identity.TargetID, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.state[target]
	if c == nil || c.openTill.IsZero() {
		return true
	}
	if now.Before(c.openTill) {
		return false
	}
	// Half open: one call decides; a failure reopens at once.
	c.openTill = time.Time{}
	c.failures = config.ActionBreakerFailures - 1
	return true
}

// Record notes a call's outcome.
func (b *Breaker) Record(target identity.TargetID, ok bool, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		delete(b.state, target)
		return
	}
	if b.state == nil {
		b.state = map[identity.TargetID]*circuit{}
	}
	c := b.state[target]
	if c == nil {
		c = &circuit{}
		b.state[target] = c
	}
	c.failures++
	if c.failures >= config.ActionBreakerFailures {
		c.openTill = now.Add(config.ActionBreakerOpen)
	}
}
