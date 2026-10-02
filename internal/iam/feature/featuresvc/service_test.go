package featuresvc_test

import (
	"context"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache/cachememory"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/feature"
	"github.com/Abraxas-365/iamkit/internal/iam/feature/featuresvc"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type memory struct {
	rows  map[string]feature.Override
	reads int
}

func (m *memory) Overrides(ctx context.Context, environment identity.EnvironmentID) ([]feature.Override, error) {
	m.reads++
	out := []feature.Override{}
	for _, o := range m.rows {
		out = append(out, o)
	}
	return out, nil
}

func (m *memory) Override(ctx context.Context, environment identity.EnvironmentID, name string) (*feature.Override, error) {
	m.reads++
	if o, ok := m.rows[name]; ok {
		return &o, nil
	}
	return nil, nil
}

func (m *memory) Save(ctx context.Context, mu feature.Mutation, name string, enabled bool) error {
	m.rows[name] = feature.Override{Name: name, Enabled: enabled, UpdatedAt: time.Now()}
	return nil
}

func (m *memory) Delete(ctx context.Context, mu feature.Mutation, name string) error {
	delete(m.rows, name)
	return nil
}

func isType(err error, t errx.Type) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Type == t
}

func TestService(t *testing.T) {
	ctx := context.Background()
	repo := &memory{rows: map[string]feature.Override{"removed_flag": {Name: "removed_flag", Enabled: true}}}
	s := featuresvc.New(repo, feature.Deployment{config.FeatureBetaLanguages: false})
	env := identity.NewEnvironmentID()
	m := feature.Mutation{Environment: env}

	list, err := s.List(ctx, env)
	if err != nil || len(list) != len(config.Flags) {
		t.Fatalf("list = %v %v", list, err)
	}
	if on, _ := s.Enabled(ctx, env, config.FeatureBetaLanguages); on {
		t.Fatal("deployment value ignored")
	}
	on := true
	f, err := s.Set(ctx, m, config.FeatureBetaLanguages, feature.Set{Enabled: &on})
	if err != nil || !f.Enabled || f.Environment == nil {
		t.Fatalf("set = %+v %v", f, err)
	}
	if f, err = s.Reset(ctx, m, config.FeatureBetaLanguages); err != nil || f.Enabled || f.Environment != nil {
		t.Fatalf("reset = %+v %v", f, err)
	}

	if _, err := s.Set(ctx, m, config.FeatureBetaLanguages, feature.Set{}); !isType(err, errx.TypeValidation) {
		t.Fatalf("missing enabled = %v", err)
	}
	if _, err := s.Set(ctx, m, "nope", feature.Set{Enabled: &on}); !isType(err, errx.TypeNotFound) {
		t.Fatalf("unknown = %v", err)
	}
	if _, err := s.Set(ctx, m, config.FeatureSAMLIdP, feature.Set{Enabled: &on}); !isType(err, errx.TypeValidation) {
		t.Fatalf("deployment-scoped = %v", err)
	}
	// Deployment-scoped flags never read the database.
	reads := repo.reads
	if on, err := s.Enabled(ctx, env, config.FeatureSAMLIdP); err != nil || !on || repo.reads != reads {
		t.Fatalf("saml_idp = %v %v (reads %d→%d)", on, err, reads, repo.reads)
	}
}

func TestServiceCache(t *testing.T) {
	ctx := context.Background()
	repo := &memory{rows: map[string]feature.Override{}}
	s := featuresvc.New(repo, feature.Deployment{})
	s.SetCache(cachememory.New())
	env := identity.NewEnvironmentID()
	m := feature.Mutation{Environment: env}

	for range 3 {
		if on, err := s.Enabled(ctx, env, config.FeatureBetaLanguages); err != nil || !on {
			t.Fatalf("enabled = %v %v", on, err)
		}
	}
	if repo.reads != 1 {
		t.Fatalf("%d reads, want 1", repo.reads)
	}
	// Writes drop the environment's entry.
	off := false
	if _, err := s.Set(ctx, m, config.FeatureBetaLanguages, feature.Set{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.Enabled(ctx, env, config.FeatureBetaLanguages); on {
		t.Fatal("stale override after Set")
	}
	if _, err := s.Reset(ctx, m, config.FeatureBetaLanguages); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.Enabled(ctx, env, config.FeatureBetaLanguages); !on {
		t.Fatal("stale override after Reset")
	}
}
