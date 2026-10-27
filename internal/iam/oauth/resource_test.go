package oauth

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// canonicalVectors are the cases every implementation of the resource
// canonicalization shares (server, Go SDK, Node SDK).
type canonicalVectors struct {
	Cases []struct {
		Name      string  `json:"name"`
		Input     string  `json:"input"`
		Canonical *string `json:"canonical"`
	} `json:"cases"`
}

func TestCanonicalResourceSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../sdk/resourceserver/testdata/canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors canonicalVectors
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) < 20 {
		t.Fatalf("only %d vectors", len(vectors.Cases))
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := CanonicalResource(tc.Input)
			switch {
			case tc.Canonical == nil && err == nil:
				t.Fatalf("CanonicalResource(%q) = %q, want an error", tc.Input, got)
			case tc.Canonical != nil && err != nil:
				t.Fatalf("CanonicalResource(%q): %v", tc.Input, err)
			case tc.Canonical != nil && got != *tc.Canonical:
				t.Fatalf("CanonicalResource(%q) = %q, want %q", tc.Input, got, *tc.Canonical)
			}
			if tc.Canonical != nil {
				// Canonical forms are fixed points.
				again, err := CanonicalResource(got)
				if err != nil || again != got {
					t.Fatalf("not idempotent: %q -> %q (%v)", got, again, err)
				}
			}
		})
	}
}

func TestSameResource(t *testing.T) {
	if !SameResource("https://MCP.example.com:443/mcp/", "https://mcp.example.com/mcp") {
		t.Fatal("equivalent URIs differ")
	}
	if SameResource("https://mcp.example.com/mcp", "https://mcp.example.com/MCP") {
		t.Fatal("path case ignored")
	}
	if SameResource("http://mcp.example.com/mcp", "http://mcp.example.com/mcp") {
		t.Fatal("invalid URIs matched")
	}
}

// TestProtectedTargetDeadline: a refresh holds a grant to min(stored end,
// start + current lifetime), so a lowered ceiling cuts grants already issued
// and a raised one never extends them.
func TestProtectedTargetDeadline(t *testing.T) {
	day := 24 * time.Hour
	now := time.Now()
	started := now.Add(-40 * day)
	stored := started.Add(90 * day)
	cases := []struct {
		name     string
		lifetime time.Duration
		started  time.Time
		want     time.Time
	}{
		{"ceiling cut to 30 days ends a 40-day-old grant", 30 * day, started, started.Add(30 * day)},
		{"unchanged ceiling keeps the stored end", 90 * day, started, stored},
		{"raised ceiling never extends", 180 * day, started, stored},
		{"grant without a recorded start keeps the stored end", 30 * day, time.Time{}, stored},
	}
	for _, tc := range cases {
		target := &ProtectedTarget{Lifetime: tc.lifetime}
		if got := target.Deadline(tc.started, stored); !got.Equal(tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if ValidateSession((&ProtectedTarget{Lifetime: 30 * day}).Deadline(started, stored)) == nil {
		t.Fatal("a grant past the lowered lifetime still validates")
	}
}
