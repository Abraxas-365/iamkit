package cache_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/cache/cachememory"
)

// broken is a store that is down.
type broken struct{}

func (broken) Get(context.Context, string) ([]byte, bool, error) {
	return nil, false, errors.New("down")
}
func (broken) Set(context.Context, string, []byte, time.Duration) error {
	return errors.New("down")
}
func (broken) Delete(context.Context, ...string) error { return errors.New("down") }

type row struct {
	Name  string
	Count int
}

func TestRead(t *testing.T) {
	ctx := context.Background()
	loads := 0
	load := func() (row, error) { loads++; return row{"a", loads}, nil }

	store := cachememory.New()
	for range 3 {
		if got, err := cache.Read(ctx, store, "t:a", time.Minute, load); err != nil || got != (row{"a", 1}) {
			t.Fatalf("read = %+v %v", got, err)
		}
	}
	cache.Forget(ctx, store, "t:a")
	if got, _ := cache.Read(ctx, store, "t:a", time.Minute, load); got.Count != 2 {
		t.Fatalf("after forget = %+v", got)
	}

	// No store and a store that is down both read through.
	for _, s := range []cache.Store{nil, broken{}} {
		before := loads
		for range 2 {
			if _, err := cache.Read(ctx, s, "t:a", time.Minute, load); err != nil {
				t.Fatal(err)
			}
		}
		if loads != before+2 {
			t.Fatalf("%T: %d loads, want 2", s, loads-before)
		}
		cache.Forget(ctx, s, "t:a")
	}

	// Errors are returned and not cached.
	fail := errors.New("db down")
	if _, err := cache.Read(ctx, store, "t:b", time.Minute, func() (row, error) { return row{}, fail }); !errors.Is(err, fail) {
		t.Fatalf("error = %v", err)
	}
	if got, _ := cache.Read(ctx, store, "t:b", time.Minute, load); got.Name != "a" {
		t.Fatalf("error cached: %+v", got)
	}

	// An entry that no longer decodes is reloaded.
	_ = store.Set(ctx, "t:c", []byte("{not json"), time.Minute)
	if got, err := cache.Read(ctx, store, "t:c", time.Minute, load); err != nil || got.Name != "a" {
		t.Fatalf("undecodable = %+v %v", got, err)
	}
}
