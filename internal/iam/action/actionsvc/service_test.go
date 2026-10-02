package actionsvc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// repository serves Bound and records calls; the rest is unused.
type repository struct {
	action.Repository
	bound []action.Bound
	calls []action.Call
}

func (r *repository) Bound(context.Context, identity.EnvironmentID, string) ([]action.Bound, error) {
	return r.bound, nil
}
func (r *repository) RecordCall(_ context.Context, c action.Call) error {
	r.calls = append(r.calls, c)
	return nil
}

// caller answers per URL.
type caller map[string]action.Answer

func (c caller) Call(_ context.Context, m action.Outbound) action.Answer { return c[m.URL] }

type cipher struct{}

func (cipher) Seal(plain []byte) (string, error)  { return string(plain), nil }
func (cipher) Open(sealed string) ([]byte, error) { return []byte(sealed), nil }

type features bool

func (f features) Enabled(context.Context, identity.EnvironmentID, string) (bool, error) {
	return bool(f), nil
}

func target(url, kind string, interrupt bool) action.Bound {
	return action.Bound{Target: action.Target{ID: identity.NewTargetID(), URL: url, Kind: kind, TimeoutMS: 1000, InterruptOnError: interrupt},
		Sealed: []string{"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"}}
}

func ok(body string) action.Answer { return action.Answer{Status: 200, Body: []byte(body)} }

func service(repo *repository, answers caller, on bool) *Service {
	s := New(repo, answers, cipher{}, nil, features(on))
	s.background = func(f func()) { f() }
	return s
}

func code(err error) string {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestRunMergesInOrder(t *testing.T) {
	repo := &repository{bound: []action.Bound{
		target("https://a", action.KindCall, false),
		target("https://b", action.KindWebhook, false),
		target("https://c", action.KindCall, false),
		target("https://d", action.KindAsync, false),
	}}
	answers := caller{
		"https://a": ok(`{"claims":{"tier":"silver","team":"x"}}`),
		"https://b": ok(`{"claims":{"ignored":true}}`),
		"https://c": ok(`{"claims":{"tier":"gold"}}`),
		"https://d": ok(`{"deny":true}`),
	}
	built := 0
	result, err := service(repo, answers, true).Run(context.Background(), identity.NewEnvironmentID(), action.PreAccessToken, func() action.Input {
		built++
		return action.Input{}
	})
	if err != nil {
		t.Fatal(err)
	}
	var tier string
	_ = json.Unmarshal(result.Claims["tier"], &tier)
	if tier != "gold" || result.Claims["team"] == nil || result.Claims["ignored"] != nil || built != 1 {
		t.Fatalf("result %v, built %d", result.Claims, built)
	}
	if len(repo.calls) != 4 {
		t.Fatalf("calls logged: %d", len(repo.calls))
	}
}

func TestRunDeny(t *testing.T) {
	repo := &repository{bound: []action.Bound{target("https://a", action.KindCall, false), target("https://b", action.KindCall, false)}}
	_, err := service(repo, caller{"https://a": ok(`{"deny":true,"message":"Blocked country"}`)}, true).
		Run(context.Background(), identity.NewEnvironmentID(), action.PreSignIn, func() action.Input { return action.Input{} })
	var e *errx.Error
	if !errx.As(err, &e) || e.Code != "ACTION_DENIED" || e.Message != "Blocked country" || e.HTTPStatus != 403 {
		t.Fatalf("deny: %v", err)
	}
	if len(repo.calls) != 1 || repo.calls[0].Outcome != action.OutcomeDenied {
		t.Fatalf("later target called: %+v", repo.calls)
	}
}

func TestRunFailures(t *testing.T) {
	env := identity.NewEnvironmentID()
	build := func() action.Input { return action.Input{} }
	// A failing target without interrupt_on_error is skipped.
	repo := &repository{bound: []action.Bound{target("https://down", action.KindCall, false), target("https://a", action.KindCall, false)}}
	answers := caller{"https://down": {Status: 500}, "https://a": ok(`{"claims":{"x":1}}`)}
	result, err := service(repo, answers, true).Run(context.Background(), env, action.PreAccessToken, build)
	if err != nil || result.Claims["x"] == nil || repo.calls[0].Outcome != action.OutcomeFailed {
		t.Fatalf("non-interrupting: %v %v", result, err)
	}
	// An invalid answer (reserved claim) is a failure; interrupting stops.
	repo = &repository{bound: []action.Bound{target("https://bad", action.KindCall, true)}}
	_, err = service(repo, caller{"https://bad": ok(`{"claims":{"sub":"evil"}}`)}, true).Run(context.Background(), env, action.PreAccessToken, build)
	if code(err) != "ACTION_FAILED" || repo.calls[0].Error == "" {
		t.Fatalf("interrupting: %v %+v", err, repo.calls)
	}
	// Denial where the condition takes none.
	repo = &repository{bound: []action.Bound{target("https://a", action.KindCall, false)}}
	if _, err = service(repo, caller{"https://a": ok(`{"deny":true}`)}, true).Run(context.Background(), env, action.PreUserInfo, build); err != nil {
		t.Fatalf("userinfo deny not ignored: %v", err)
	}
}

func TestRunBreaker(t *testing.T) {
	bound := target("https://down", action.KindCall, false)
	repo := &repository{bound: []action.Bound{bound}}
	s := service(repo, caller{"https://down": {Error: "timed out"}}, true)
	for range 6 {
		_, _ = s.Run(context.Background(), identity.NewEnvironmentID(), action.PreSignIn, func() action.Input { return action.Input{} })
	}
	if last := repo.calls[len(repo.calls)-1]; last.Outcome != action.OutcomeSkipped {
		t.Fatalf("breaker did not open: %+v", last)
	}
}

func TestRunOff(t *testing.T) {
	repo := &repository{bound: []action.Bound{target("https://a", action.KindCall, false)}}
	if _, err := service(repo, caller{"https://a": ok(`{"deny":true}`)}, false).Run(context.Background(), identity.NewEnvironmentID(), action.PreSignIn, func() action.Input {
		t.Fatal("built with the feature off")
		return action.Input{}
	}); err != nil || len(repo.calls) != 0 {
		t.Fatalf("feature off: %v", err)
	}
	if _, err := service(&repository{}, nil, true).Run(context.Background(), identity.NewEnvironmentID(), "function:nope", nil); err == nil {
		t.Fatal("unknown condition accepted")
	}
}
