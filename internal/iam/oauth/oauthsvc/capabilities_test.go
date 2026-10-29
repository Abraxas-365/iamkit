package oauthsvc

import (
	"context"
	"errors"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/cache/cachememory"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type fakeCapabilities struct {
	environments []identity.EnvironmentID
	err          error
	reads        int
}

func (f *fakeCapabilities) ClientMetadataEnvironments(context.Context) ([]identity.EnvironmentID, error) {
	f.reads++
	return f.environments, f.err
}

type flagsByEnvironment map[identity.EnvironmentID]bool

func (f flagsByEnvironment) Enabled(_ context.Context, e identity.EnvironmentID, _ string) (bool, error) {
	return f[e], nil
}

func TestCapabilitiesClientMetadata(t *testing.T) {
	ctx := context.Background()
	a, b := identity.NewEnvironmentID(), identity.NewEnvironmentID()
	for _, tc := range []struct {
		name         string
		environments []identity.EnvironmentID
		flags        oauth.Features
		want         bool
	}{
		{"no protected resource allows documents", nil, flagsByEnvironment{a: true}, false},
		{"allowed but the feature is off there", []identity.EnvironmentID{a}, flagsByEnvironment{a: false, b: true}, false},
		{"feature on in another environment is not enough", []identity.EnvironmentID{a}, flagsByEnvironment{b: true}, false},
		{"allowed and on in the same environment", []identity.EnvironmentID{a, b}, flagsByEnvironment{b: true}, true},
		{"no feature service: allowed is enough", []identity.EnvironmentID{a}, nil, true},
	} {
		got, err := NewCapabilities(&fakeCapabilities{environments: tc.environments}, tc.flags, nil).Offered(ctx)
		if err != nil || got.ClientMetadataDocuments != tc.want {
			t.Errorf("%s: %+v, %v", tc.name, got, err)
		}
	}
	if _, err := NewCapabilities(&fakeCapabilities{err: errors.New("db down")}, nil, nil).Offered(ctx); err == nil {
		t.Error("a failing read must not be answered as 'not offered'")
	}
}

func TestCapabilitiesAreCachedBriefly(t *testing.T) {
	repo := &fakeCapabilities{environments: []identity.EnvironmentID{identity.NewEnvironmentID()}}
	c := NewCapabilities(repo, nil, cachememory.New())
	for range 5 {
		if got, err := c.Offered(context.Background()); err != nil || !got.ClientMetadataDocuments {
			t.Fatal(got, err)
		}
	}
	if repo.reads != 1 {
		t.Fatalf("reads = %d", repo.reads)
	}
	// A failure is not cached.
	failing := &fakeCapabilities{err: errors.New("x")}
	c = NewCapabilities(failing, nil, cachememory.New())
	_, _ = c.Offered(context.Background())
	_, _ = c.Offered(context.Background())
	if failing.reads != 2 {
		t.Fatalf("failing reads = %d", failing.reads)
	}
}
