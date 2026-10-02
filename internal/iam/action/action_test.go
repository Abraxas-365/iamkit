package action

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestTargetCreateValidate(t *testing.T) {
	ok := TargetCreate{Name: "Risk", URL: "https://hooks.example/risk"}.Normalize()
	if ok.Kind != KindCall || ok.TimeoutMS != int(config.ActionTimeout/time.Millisecond) {
		t.Fatalf("defaults: %+v", ok)
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]TargetCreate{
		"no name":         {URL: "https://a.example"},
		"plain http":      {Name: "x", URL: "http://a.example"},
		"credentials":     {Name: "x", URL: "https://u:p@a.example"},
		"kind":            {Name: "x", URL: "https://a.example", Kind: "grpc"},
		"short timeout":   {Name: "x", URL: "https://a.example", TimeoutMS: 50},
		"long timeout":    {Name: "x", URL: "https://a.example", TimeoutMS: 20000},
		"async interrupt": {Name: "x", URL: "https://a.example", Kind: KindAsync, InterruptOnError: true},
	} {
		if c.Normalize().Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (TargetCreate{Name: "dev", URL: "http://localhost:8080/hook"}).Normalize().Validate(); err != nil {
		t.Fatalf("loopback http: %v", err)
	}
}

func TestTargetUpdateApply(t *testing.T) {
	async := KindAsync
	if _, err := (TargetUpdate{Kind: &async}).Apply(Target{Kind: KindCall, InterruptOnError: true}); err == nil {
		t.Fatal("an interrupting target became async")
	}
}

func TestExecutionSetValidate(t *testing.T) {
	a, b := identity.NewTargetID(), identity.NewTargetID()
	if err := (ExecutionSet{Targets: []identity.TargetID{a, b}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []ExecutionSet{{}, {Targets: []identity.TargetID{a, a}}, {Targets: make([]identity.TargetID, 6)}} {
		if s.Validate() == nil {
			t.Errorf("accepted %v", s.Targets)
		}
	}
}

func condition(t *testing.T, name string) Condition {
	t.Helper()
	c, ok := FindCondition(name)
	if !ok {
		t.Fatalf("no condition %s", name)
	}
	return c
}

func TestResponseCheck(t *testing.T) {
	claims := func(raw string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	cases := []struct {
		name      string
		condition string
		response  Response
		ok        bool
	}{
		{"allow", PreSignIn, Response{}, true},
		{"deny", PreSignIn, Response{Deny: true, Message: "no"}, true},
		{"deny not allowed", PreUserInfo, Response{Deny: true}, false},
		{"long message", PreSignIn, Response{Deny: true, Message: strings.Repeat("x", 201)}, false},
		{"claims", PreAccessToken, Response{Claims: claims(`{"tier":"gold","roles":["a"]}`)}, true},
		{"claims not allowed", PreSignIn, Response{Claims: claims(`{"tier":"gold"}`)}, false},
		{"reserved", PreAccessToken, Response{Claims: claims(`{"sub":"x"}`)}, false},
		{"reserved permissions", PreIDToken, Response{Claims: claims(`{"permissions":[]}`)}, false},
		{"bad name", PreAccessToken, Response{Claims: claims(`{"has space":1}`)}, false},
		{"too big", PreAccessToken, Response{Claims: map[string]json.RawMessage{"big": json.RawMessage(`"` + strings.Repeat("x", 5000) + `"`)}}, false},
		{"patch", PostFederation, Response{Patch: claims(`{"name":"Ada"}`)}, true},
		{"patch field", PostFederation, Response{Patch: claims(`{"email":"a@b.c"}`)}, false},
		{"patch type", UserCreate, Response{Patch: claims(`{"name":1}`)}, false},
	}
	for _, c := range cases {
		err := c.response.Check(condition(t, c.condition))
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

func TestResultMerge(t *testing.T) {
	var r Result
	r.Merge(Response{Claims: map[string]json.RawMessage{"a": json.RawMessage(`1`), "b": json.RawMessage(`"x"`)}, Patch: map[string]json.RawMessage{"name": json.RawMessage(`"First"`)}})
	r.Merge(Response{Claims: map[string]json.RawMessage{"b": json.RawMessage(`"y"`)}, Patch: map[string]json.RawMessage{"name": json.RawMessage(`"Second"`)}})
	values := r.ClaimValues()
	if values["a"] != float64(1) || values["b"] != "y" || r.Patch["name"] != "Second" {
		t.Fatalf("merge: %v %v", values, r.Patch)
	}
}

func TestDenyMessage(t *testing.T) {
	if (Response{Message: "  "}).DenyMessage() == "" || (Response{Message: "Blocked"}).DenyMessage() != "Blocked" {
		t.Fatal("deny message")
	}
}

func TestReservedClaimsCoverTokenClaims(t *testing.T) {
	for _, name := range []string{"iss", "sub", "aud", "exp", "iat", "jti", "sid", "permissions", "environment_id", "organization_id", "amr", "auth_time", "purpose", "act", "application_id", "resource_id", "oauth_client_id"} {
		found := false
		for _, r := range ReservedClaims {
			found = found || r == name
		}
		if !found {
			t.Errorf("%s is not reserved", name)
		}
	}
}

func TestBreaker(t *testing.T) {
	var b Breaker
	target := identity.NewTargetID()
	now := time.Unix(1000, 0)
	for range config.ActionBreakerFailures - 1 {
		b.Record(target, false, now)
	}
	if !b.Allow(target, now) {
		t.Fatal("open before the threshold")
	}
	b.Record(target, false, now)
	if b.Allow(target, now.Add(time.Second)) {
		t.Fatal("closed after the threshold")
	}
	later := now.Add(config.ActionBreakerOpen)
	if !b.Allow(target, later) {
		t.Fatal("no half-open try")
	}
	b.Record(target, false, later)
	if b.Allow(target, later.Add(time.Second)) {
		t.Fatal("a failed half-open try did not reopen")
	}
	again := later.Add(config.ActionBreakerOpen)
	if !b.Allow(target, again) {
		t.Fatal("no second half-open try")
	}
	b.Record(target, true, again)
	b.Record(target, false, again)
	if !b.Allow(target, again) {
		t.Fatal("a success did not reset the count")
	}
	if !b.Allow(identity.NewTargetID(), again) {
		t.Fatal("unrelated target blocked")
	}
}
