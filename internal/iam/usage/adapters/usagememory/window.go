// Package usagememory counts per-minute limits in this process (each
// replica keeps its own windows).
package usagememory

import (
	"context"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/usage"
)

type window struct {
	start time.Time
	count int64
}

// Window is a fixed-window counter per key; stale windows are dropped as
// new ones start.
type Window struct {
	mu      sync.Mutex
	windows map[string]*window
	now     func() time.Time
	swept   time.Time
}

var _ usage.Window = (*Window)(nil)

func New() *Window { return &Window{windows: map[string]*window{}, now: time.Now} }

func (w *Window) Take(_ context.Context, key string, max int64, length time.Duration) (bool, error) {
	now := w.now()
	start := now.Truncate(length)
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Sub(w.swept) > length {
		for k, x := range w.windows {
			if x.start.Before(start) {
				delete(w.windows, k)
			}
		}
		w.swept = now
	}
	x, ok := w.windows[key]
	if !ok || !x.start.Equal(start) {
		x = &window{start: start}
		w.windows[key] = x
	}
	if x.count >= max {
		return false, nil
	}
	x.count++
	return true, nil
}
