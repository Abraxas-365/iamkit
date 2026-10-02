package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestMetadataLimits(t *testing.T) {
	for _, key := range []string{"a", "plan.tier", "x_y-z", strings.Repeat("k", 64)} {
		if err := MetadataKey(key); err != nil {
			t.Fatalf("%q: %v", key, err)
		}
	}
	for _, key := range []string{"", "a b", "ñ", "a/b", strings.Repeat("k", 65)} {
		if MetadataKey(key) == nil {
			t.Fatalf("%q accepted", key)
		}
	}
	if err := ValidateMetadata(json.RawMessage(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if ValidateMetadata(json.RawMessage(`[1]`)) == nil || ValidateMetadata(json.RawMessage(`{"a b":1}`)) == nil {
		t.Fatal("bad metadata accepted")
	}
	big := `{"a":"` + strings.Repeat("x", MetadataMaxValue) + `"}`
	if ValidateMetadata(json.RawMessage(big)) == nil {
		t.Fatal("oversized value accepted")
	}
	many := map[string]int{}
	for i := 0; i <= MetadataMaxKeys; i++ {
		many[fmt.Sprint("k", i)] = i
	}
	raw, _ := json.Marshal(many)
	if ValidateMetadata(raw) == nil {
		t.Fatal("65 keys accepted")
	}
}

func TestSetAndDeleteMetadata(t *testing.T) {
	raw, err := SetMetadata(json.RawMessage(`{"a":1}`), "b", json.RawMessage(` {"x":true} `))
	if err != nil || string(raw) != `{"a":1,"b":{"x":true}}` {
		t.Fatalf("%s %v", raw, err)
	}
	if _, err = SetMetadata(raw, "c", json.RawMessage(`nope`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if value, ok := MetadataValue(raw, "b"); !ok || string(value) != `{"x":true}` {
		t.Fatalf("value %s", value)
	}
	raw, found, err := DeleteMetadata(raw, "a")
	if err != nil || !found || string(raw) != `{"b":{"x":true}}` {
		t.Fatalf("%s %v %v", raw, found, err)
	}
	if _, found, _ = DeleteMetadata(raw, "a"); found {
		t.Fatal("deleted twice")
	}
	// Totals: 9 values of 4000 bytes exceed 32 KiB.
	raw = json.RawMessage(`{}`)
	value := json.RawMessage(`"` + strings.Repeat("x", 3998) + `"`)
	for i := 0; i < 9; i++ {
		raw, err = SetMetadata(raw, fmt.Sprint("k", i), value)
		if i < 8 && err != nil {
			t.Fatal(err)
		}
	}
	if err == nil {
		t.Fatal("32 KiB exceeded")
	}
}
