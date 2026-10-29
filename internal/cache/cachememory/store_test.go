package cachememory

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	s := New()
	s.now = func() time.Time { return now }

	value := []byte("v")
	_ = s.Set(ctx, "a", value, time.Second)
	value[0] = 'x' // the store keeps its own copy
	if got, ok, _ := s.Get(ctx, "a"); !ok || string(got) != "v" {
		t.Fatalf("get = %q %v", got, ok)
	}
	now = now.Add(time.Second)
	if _, ok, _ := s.Get(ctx, "a"); ok {
		t.Fatal("expired entry returned")
	}

	_ = s.Set(ctx, "b", []byte("1"), time.Hour)
	_ = s.Set(ctx, "c", []byte("2"), time.Second)
	_ = s.Delete(ctx, "b", "missing")
	if _, ok, _ := s.Get(ctx, "b"); ok {
		t.Fatal("deleted entry returned")
	}
	// Writes sweep expired entries.
	now = now.Add(2 * time.Minute)
	_ = s.Set(ctx, "d", []byte("3"), time.Hour)
	if len(s.entries) != 1 {
		t.Fatalf("entries after sweep = %d", len(s.entries))
	}
	s.Reset()
	if _, ok, _ := s.Get(ctx, "d"); ok {
		t.Fatal("reset kept an entry")
	}
}

func TestSetNX(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	s := New()
	s.now = func() time.Time { return now }

	if ok, err := s.SetNX(ctx, "k", []byte("a"), time.Minute); err != nil || !ok {
		t.Fatalf("first = %v %v", ok, err)
	}
	if ok, _ := s.SetNX(ctx, "k", []byte("b"), time.Minute); ok {
		t.Fatal("second claim won")
	}
	if got, _, _ := s.Get(ctx, "k"); string(got) != "a" {
		t.Fatalf("value = %q", got)
	}
	now = now.Add(time.Minute)
	if ok, _ := s.SetNX(ctx, "k", []byte("c"), time.Minute); !ok {
		t.Fatal("claim after expiry lost")
	}
	// A Set entry blocks, a Delete frees.
	_ = s.Set(ctx, "set", []byte("x"), time.Hour)
	if ok, _ := s.SetNX(ctx, "set", []byte("y"), time.Hour); ok {
		t.Fatal("claim over a Set entry")
	}
	_ = s.Delete(ctx, "set")
	if ok, _ := s.SetNX(ctx, "set", []byte("y"), time.Hour); !ok {
		t.Fatal("claim after Delete lost")
	}

	// Exactly one of many concurrent claimants wins.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := s.SetNX(ctx, "race", []byte("1"), time.Hour); ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("winners = %d", wins.Load())
	}
}
