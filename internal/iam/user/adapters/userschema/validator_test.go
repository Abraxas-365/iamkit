package userschema

import (
	"encoding/json"
	"strings"
	"testing"
)

const schema = `{"type":"object","additionalProperties":false,"required":["department"],"properties":{
	"department":{"type":"string","enum":["sales","eng"]},
	"started":{"type":"string","format":"date"},
	"tags":{"$ref":"#/$defs/tags"}},
	"$defs":{"tags":{"type":"array","items":{"type":"string"},"maxItems":2}}}`

func TestValidate(t *testing.T) {
	v := Validator{}
	if err := v.Check(json.RawMessage(schema)); err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(json.RawMessage(schema), json.RawMessage(`{"department":"eng","started":"2024-02-01","tags":["a"]}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{}`, `{"department":"hr"}`, `{"department":"eng","extra":1}`,
		`{"department":"eng","started":"yesterday"}`, `{"department":"eng","tags":["a","b","c"]}`,
	} {
		err := v.Validate(json.RawMessage(schema), json.RawMessage(bad))
		if err == nil {
			t.Fatalf("%s accepted", bad)
		}
		if !strings.Contains(err.Error(), "profile does not match the user schema") {
			t.Fatalf("%s: %v", bad, err)
		}
	}
}

func TestCheckRefusesRemoteReferences(t *testing.T) {
	v := Validator{}
	for _, bad := range []string{
		`{"type":"object","properties":{"a":{"$ref":"https://example.com/schema.json"}}}`,
		`{"type":"object","properties":{"a":{"$ref":"file:///etc/passwd"}}}`,
		`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`,
		`{"type":"object","properties":{"a":{"type":"nope"}}}`,
		`not json`,
	} {
		if err := v.Check(json.RawMessage(bad)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}
