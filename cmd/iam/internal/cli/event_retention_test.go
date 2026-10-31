package cli

import (
	"reflect"
	"strings"
	"testing"
)

const retentionJSON = `{"security_retention_seconds":null,"default_retention_seconds":604800,"ceilings":{"security":31536000,"default":7776000},"effective":{"security":31536000,"default":604800}}`

func TestEventRetentionGet(t *testing.T) {
	out, _, seen, err := runCLI(t, ok(200, retentionJSON), "-o", "table", "event-retention", "get")
	if err != nil || seen[0].Method != "GET" || seen[0].Path != base+"/event-retention" {
		t.Fatalf("%v %+v", err, seen)
	}
	for _, want := range []string{"security", "365d", "default", "7d", "90d"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

func TestEventRetentionSet(t *testing.T) {
	// A flag left out keeps the stored value (the PUT replaces both).
	_, _, seen, err := runCLI(t, ok(200, retentionJSON), "event-retention", "set", "--security", "30d")
	if err != nil || len(seen) != 2 || seen[1].Method != "PUT" || seen[1].Path != base+"/event-retention" {
		t.Fatalf("%v %+v", err, seen)
	}
	want := map[string]any{"security_retention_seconds": float64(30 * 86400), "default_retention_seconds": float64(604800)}
	if !reflect.DeepEqual(seen[1].Body, want) {
		t.Fatalf("body = %v", seen[1].Body)
	}
	_, _, seen, err = runCLI(t, ok(200, retentionJSON), "event-retention", "set", "--default", "default", "--security", "720h")
	want = map[string]any{"security_retention_seconds": float64(720 * 3600), "default_retention_seconds": nil}
	if err != nil || !reflect.DeepEqual(seen[1].Body, want) {
		t.Fatalf("%v %v", err, seen)
	}
	if _, _, _, err = runCLI(t, ok(200, retentionJSON), "event-retention", "set"); err == nil {
		t.Fatal("set without flags accepted")
	}
	if _, _, _, err = runCLI(t, ok(200, retentionJSON), "event-retention", "set", "--default", "soon"); err == nil {
		t.Fatal("bad duration accepted")
	}
}
