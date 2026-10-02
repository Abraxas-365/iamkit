package actionsvc

import (
	"context"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache/cachememory"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// counting serves Bound from a map per condition, counts reads and
// accepts the writes that change bindings.
type counting struct {
	repository
	byCondition map[string][]action.Bound
	reads       int
}

func (r *counting) Bound(_ context.Context, _ identity.EnvironmentID, condition string) ([]action.Bound, error) {
	r.reads++
	return r.byCondition[condition], nil
}
func (r *counting) FindTarget(context.Context, identity.EnvironmentID, identity.TargetID) (action.Target, error) {
	return action.Target{Name: "t", URL: "https://a", Kind: action.KindCall, TimeoutMS: 1000}, nil
}
func (r *counting) UpdateTarget(context.Context, action.Mutation, action.Target) error { return nil }
func (r *counting) DeleteTarget(context.Context, action.Mutation, identity.TargetID) error {
	return nil
}
func (r *counting) RotateTargetSecret(context.Context, action.Mutation, identity.TargetID, string, time.Time) error {
	return nil
}
func (r *counting) SetExecution(_ context.Context, _ action.Mutation, condition string, _ []identity.TargetID) (action.Execution, error) {
	return action.Execution{Condition: condition}, nil
}
func (r *counting) DeleteExecution(context.Context, action.Mutation, string) error { return nil }

type secrets struct{}

func (secrets) Generate() (string, error) { return "whsec_new", nil }

func TestRunCachesBindings(t *testing.T) {
	ctx := context.Background()
	env := identity.NewEnvironmentID()
	repo := &counting{byCondition: map[string][]action.Bound{action.PreAccessToken: {target("https://a", action.KindCall, false)}}}
	s := New(repo, caller{"https://a": ok(`{"claims":{"tier":"gold"}}`)}, cipher{}, secrets{}, features(true))
	s.background = func(f func()) { f() }
	s.SetCache(cachememory.New())
	run := func() {
		t.Helper()
		result, err := s.Run(ctx, env, action.PreAccessToken, func() action.Input { return action.Input{} })
		if err != nil || result.Claims["tier"] == nil {
			t.Fatalf("run = %+v %v", result, err)
		}
	}
	run()
	run()
	if repo.reads != 1 {
		t.Fatalf("%d reads, want 1 (cached)", repo.reads)
	}
	m := action.Mutation{Environment: env}
	id := identity.NewTargetID()
	name := "renamed"
	for label, write := range map[string]func() error{
		"update target": func() error { _, err := s.UpdateTarget(ctx, m, id, action.TargetUpdate{Name: &name}); return err },
		"delete target": func() error { return s.DeleteTarget(ctx, m, id) },
		"rotate secret": func() error { _, err := s.RotateTargetSecret(ctx, m, id); return err },
		"set execution": func() error {
			_, err := s.SetExecution(ctx, m, action.PreAccessToken, action.ExecutionSet{Targets: []identity.TargetID{id}})
			return err
		},
		"delete execution": func() error { return s.DeleteExecution(ctx, m, action.PreAccessToken) },
	} {
		if err := write(); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		before := repo.reads
		run()
		if repo.reads != before+1 {
			t.Fatalf("%s did not drop the cached bindings", label)
		}
	}
}
