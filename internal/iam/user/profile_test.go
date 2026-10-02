package user

import (
	"encoding/json"
	"testing"
)

func TestProperties(t *testing.T) {
	props, err := Properties(json.RawMessage(`{"type":"object","properties":{
		"department":{"type":"string","x-iamkit-self":"read","x-iamkit-claim":"department"},
		"nickname":{"type":"string","x-iamkit-self":"write"},
		"cost_center":{"type":"string"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(props) != 3 || props[0].Name != "cost_center" || props[1].Claim != "department" || props[1].Self != SelfRead || props[2].Self != SelfWrite {
		t.Fatalf("%+v", props)
	}
	for _, bad := range []string{
		`[]`, `{"type":"string"}`,
		`{"type":"object","properties":{"a":{"x-iamkit-self":"all"}}}`,
		`{"type":"object","properties":{"a":{"x-iamkit-claim":"sub"}}}`,
		`{"type":"object","properties":{"a":{"x-iamkit-claim":"x"},"b":{"x-iamkit-claim":"x"}}}`,
		`{"type":"object","properties":{"a":{"x-iamkit-claim":"1x"}}}`,
	} {
		if _, err := Properties(json.RawMessage(bad)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestMergeProfile(t *testing.T) {
	out, err := MergeProfile(json.RawMessage(`{"a":1,"b":2}`), json.RawMessage(`{"b":null,"c":"x"}`), nil)
	if err != nil || string(out) != `{"a":1,"c":"x"}` {
		t.Fatalf("%s %v", out, err)
	}
	if _, err = MergeProfile(nil, json.RawMessage(`{"a":1}`), []string{"b"}); err == nil {
		t.Fatal("key outside allowed accepted")
	}
	if _, err = MergeProfile(nil, json.RawMessage(`[1]`), nil); err == nil {
		t.Fatal("array accepted")
	}
	picked := PickProfile(json.RawMessage(`{"a":1,"b":2}`), []string{"b", "z"})
	if len(picked) != 1 || string(picked["b"]) != "2" {
		t.Fatalf("%v", picked)
	}
}
