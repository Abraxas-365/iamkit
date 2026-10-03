package errx

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsServerError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("plain"), false},
		{Unauthorized("invalid credentials"), false},
		{Forbidden("no"), false},
		{Internal("boom"), true},
		{External("upstream"), true},
		{Wrap(errors.New("dial tcp"), "persistence failed", TypeInternal), true},
		{fmt.Errorf("context: %w", Wrap(errors.New("dial tcp"), "persistence failed", TypeInternal)), true},
	}
	for _, c := range cases {
		if got := IsServerError(c.err); got != c.want {
			t.Errorf("IsServerError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
