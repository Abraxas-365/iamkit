package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExternalClients(t *testing.T) {
	const base = "/management/v1/environments/env/"
	var seen []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		switch r.Method + " " + r.URL.Path {
		case "GET " + base + "protected-resources/p1/clients":
			w.Write([]byte(`{"items":[{"id":"c1","client_id":"https://claude.ai/oauth/claude-code-client-metadata","host":"claude.ai","admission":"pending","preset":"claude_code","preset_name":"Claude Code","access_requests":2}],"page":{"total":1,"limit":50,"offset":0}}`))
		case "GET " + base + "protected-resources/p1/clients/c1/requests":
			w.Write([]byte(`{"items":[{"user_id":"u1","email":"a@example.com","name":"Ana","requested_at":"2026-10-27T10:00:00Z"}],"page":{"total":1}}`))
		case "POST " + base + "protected-resources/p1/clients/c1/approve":
			if in["expires_at"] != "2027-01-01T00:00:00Z" || in["metadata_hash"] != "h1" {
				t.Errorf("approve body = %v", in)
			}
			w.Write([]byte(`{"id":"c1","admission":"approved","admission_expires_at":"2027-01-01T00:00:00Z","admission_source":"manual"}`))
		case "POST " + base + "protected-resources/p1/clients/c1/block":
			w.Write([]byte(`{"id":"c1","admission":"blocked"}`))
		case "POST " + base + "protected-resources/p1/clients/c1/unblock":
			w.Write([]byte(`{"id":"c1","admission":"pending"}`))
		case "DELETE " + base + "protected-resources/p1/clients/c1":
			w.WriteHeader(http.StatusNoContent)
		case "POST " + base + "protected-resources/p1/client-templates":
			if in["preset"] != "gemini_cli" {
				t.Errorf("template body = %v", in)
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"preset":"gemini_cli","mechanism":"template","client":{"client_id":"3f1e","created":true,"loopback_any_port":true}}`))
		case "GET " + base + "oauth-client-allowlist":
			w.Write([]byte(`{"items":[{"id":"e1","origin":"https://tools.example","path_prefix":"/oauth","protected_resource_id":null}],"page":{"total":1}}`))
		case "POST " + base + "oauth-client-allowlist":
			if in["origin"] != "https://tools.example" || in["path_prefix"] != "/oauth" || in["preset"] != nil || in["protected_resource_id"] != nil {
				t.Errorf("allowlist body = %v", in)
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":"e1","origin":"https://tools.example","path_prefix":"/oauth"}`))
		case "DELETE " + base + "oauth-client-allowlist/e1":
			w.WriteHeader(http.StatusNoContent)
		case "GET " + base + "oauth-client-presets":
			w.Write([]byte(`{"items":[{"key":"claude","name":"Claude (web and desktop)","mechanism":"metadata_document","network":"public","source_ranges":["160.79.104.0/21"],"warnings":["w"]}]}`))
		case "POST " + base + "oauth-client-presets":
			if in["preset"] != "claude_code" {
				t.Errorf("preset body = %v", in)
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"preset":"claude_code","mechanism":"metadata_document","allowlist_entry":{"id":"e2"}}`))
		case "GET " + base + "protected-resources/p1/impact":
			w.Write([]byte(`{"active_sessions":3,"external_clients":2}`))
		case "GET " + base + "protected-resources/p1/clients/c1/impact":
			w.Write([]byte(`{"active_sessions":4,"users":3}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remote.Close()
	env := New(remote.URL, "ik_mgmt_test").Environment("env")
	ctx := context.Background()

	clients, err := env.ExternalClients(ctx, "p1", AdmissionPending, Page{Limit: 10})
	if err != nil || len(clients.Items) != 1 || clients.Items[0].Host != "claude.ai" || clients.Items[0].PresetName != "Claude Code" || clients.Page.Total != 1 {
		t.Fatalf("clients = %+v %v", clients, err)
	}
	if reqs, err := env.ExternalClientAccessRequests(ctx, "p1", "c1", Page{}); err != nil || reqs.Items[0].Email != "a@example.com" {
		t.Fatalf("requests = %+v %v", reqs, err)
	}
	until := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if c, err := env.ApproveExternalClient(ctx, "p1", "c1", ClientApproval{ExpiresAt: &until, MetadataHash: "h1"}); err != nil || c.Admission != AdmissionApproved || c.AdmissionExpiresAt == nil {
		t.Fatalf("approve = %+v %v", c, err)
	}
	if c, err := env.BlockExternalClient(ctx, "p1", "c1"); err != nil || c.Admission != AdmissionBlocked {
		t.Fatalf("block = %+v %v", c, err)
	}
	if c, err := env.UnblockExternalClient(ctx, "p1", "c1"); err != nil || c.Admission != AdmissionPending {
		t.Fatalf("unblock = %+v %v", c, err)
	}
	if err := env.ForgetExternalClient(ctx, "p1", "c1"); err != nil {
		t.Fatal(err)
	}
	if out, err := env.CreateClientFromTemplate(ctx, "p1", "gemini_cli"); err != nil || out.Client == nil || !out.Client.Created || out.Client.ClientID != "3f1e" {
		t.Fatalf("template = %+v %v", out, err)
	}
	if list, err := env.OAuthClientAllowlist(ctx, "", Page{}); err != nil || len(list.Items) != 1 || list.Items[0].ProtectedResourceID != nil {
		t.Fatalf("allowlist = %+v %v", list, err)
	}
	if e, err := env.CreateOAuthClientAllowlistEntry(ctx, AllowlistEntryCreate{Origin: "https://tools.example", PathPrefix: "/oauth"}); err != nil || e.ID != "e1" {
		t.Fatalf("create entry = %+v %v", e, err)
	}
	if err := env.DeleteOAuthClientAllowlistEntry(ctx, "e1"); err != nil {
		t.Fatal(err)
	}
	if presets, err := env.OAuthClientPresets(ctx); err != nil || len(presets) != 1 || presets[0].Network != PresetNetworkPublic || presets[0].SourceRanges[0] != "160.79.104.0/21" {
		t.Fatalf("presets = %+v %v", presets, err)
	}
	if out, err := env.ApplyOAuthClientPreset(ctx, PresetApply{Preset: "claude_code"}); err != nil || out.Allowlist == nil || out.Allowlist.ID != "e2" {
		t.Fatalf("apply = %+v %v", out, err)
	}
	if impact, err := env.ProtectedResourceImpact(ctx, "p1"); err != nil || impact.ActiveSessions != 3 || impact.ExternalClients != 2 {
		t.Fatalf("impact = %+v %v", impact, err)
	}
	if impact, err := env.ExternalClientImpact(ctx, "p1", "c1"); err != nil || impact.ActiveSessions != 4 || impact.Users != 3 {
		t.Fatalf("client impact = %+v %v", impact, err)
	}
	if seen[0] != "GET "+base+"protected-resources/p1/clients?admission=pending&limit=10" {
		t.Errorf("first request = %q", seen[0])
	}
	if len(seen) != 14 {
		t.Fatalf("requests = %d %v", len(seen), seen)
	}
	for _, bad := range []func() error{
		func() error { _, err := env.ExternalClients(ctx, "../x", "", Page{}); return err },
		func() error { _, err := env.ApproveExternalClient(ctx, "p1", "a/b", ClientApproval{}); return err },
		func() error { return env.DeleteOAuthClientAllowlistEntry(ctx, "..") },
		func() error { _, err := env.ProtectedResourceImpact(ctx, "x?y"); return err },
		func() error { _, err := env.ExternalClientImpact(ctx, "p1", "../c"); return err },
	} {
		if bad() == nil {
			t.Error("unsafe id accepted")
		}
	}
}
