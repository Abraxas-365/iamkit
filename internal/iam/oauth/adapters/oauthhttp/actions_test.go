package oauthhttp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type answers struct{ result action.Result }

func (a answers) Run(context.Context, identity.EnvironmentID, string, func() action.Input) (action.Result, error) {
	return a.result, nil
}

// L7: even if a target's answer got past action.Response.Check (it does
// not: reserved names are refused there), the token hook never sets or
// overrides what IAMKit decides — the resource indicator, the permissions,
// the audience, the subject — and it removes only what it added.
func TestAccessHookNeverOverridesIAMKitClaims(t *testing.T) {
	raw := func(v string) json.RawMessage { return json.RawMessage(v) }
	h := &Handler{actions: answers{action.Result{Claims: map[string]json.RawMessage{
		oauth.ClaimResourceIndicator: raw(`"https://evil.example/mcp"`),
		"aud":                        raw(`["https://evil.example/mcp"]`),
		"permissions":                raw(`["mcp:tools:write","iam:everything"]`),
		"scope":                      raw(`"mcp:tools:write"`),
		"sub":                        raw(`"someone-else"`),
		"tier":                       raw(`"gold"`),
	}}}}
	session := oauthfosite.NewSession()
	session.AccessClaims.Subject = "alice"
	session.AccessClaims.Audience = []string{"https://mcp.example/mcp"}
	session.AccessClaims.Extra = map[string]any{
		oauth.ClaimResourceIndicator: "https://mcp.example/mcp",
		"permissions":                []string{"mcp:tools:read"},
	}
	// Twice: a refresh runs the hook again over the same session.
	for round := 0; round < 2; round++ {
		if err := h.accessHook(context.Background(), &oauth.Client{}, session, func() action.Input { return action.Input{} }); err != nil {
			t.Fatal(err)
		}
		extra := session.AccessClaims.Extra
		if extra[oauth.ClaimResourceIndicator] != "https://mcp.example/mcp" {
			t.Fatalf("round %d: resource = %v", round, extra[oauth.ClaimResourceIndicator])
		}
		if got, ok := extra["permissions"].([]string); !ok || len(got) != 1 || got[0] != "mcp:tools:read" {
			t.Fatalf("round %d: permissions = %v", round, extra["permissions"])
		}
		if len(session.AccessClaims.Audience) != 1 || session.AccessClaims.Audience[0] != "https://mcp.example/mcp" || session.AccessClaims.Subject != "alice" {
			t.Fatalf("round %d: aud/sub changed: %v %v", round, session.AccessClaims.Audience, session.AccessClaims.Subject)
		}
		for _, name := range []string{"aud", "scope", "sub"} {
			if _, set := extra[name]; set {
				t.Fatalf("round %d: %s injected into the claims", round, name)
			}
		}
		if extra["tier"] != "gold" || len(session.Injected) != 1 || session.Injected[0] != "tier" {
			t.Fatalf("round %d: only the plain claim should land: %v %v", round, extra, session.Injected)
		}
	}
	// A target that stops answering a claim loses it, and nothing else goes.
	h.actions = answers{}
	if err := h.accessHook(context.Background(), &oauth.Client{}, session, func() action.Input { return action.Input{} }); err != nil {
		t.Fatal(err)
	}
	if _, set := session.AccessClaims.Extra["tier"]; set || session.AccessClaims.Extra[oauth.ClaimResourceIndicator] == nil || session.AccessClaims.Extra["permissions"] == nil {
		t.Fatalf("after the target stopped: %v", session.AccessClaims.Extra)
	}
}
