package cachememory

import (
	"context"
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
