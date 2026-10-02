// Package userschema validates user profiles against an environment's JSON
// Schema (draft 2020-12). It is the only package importing the JSON Schema
// library; remote references are never fetched.
package userschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// resource is the URL the schema is registered under; nothing else loads.
const resource = "urn:iamkit:user-schema"

// Validator implements user.SchemaValidator.
type Validator struct{}

var _ user.SchemaValidator = Validator{}

// refuse is the loader of every reference that is not in the schema itself.
type refuse struct{}

func (refuse) Load(string) (any, error) {
	return nil, errors.New("remote references are not allowed")
}

func compile(schema json.RawMessage) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return nil, errx.Validation("schema must be valid JSON")
	}
	if object, ok := doc.(map[string]any); ok {
		if draft, ok := object["$schema"].(string); ok && !strings.Contains(draft, "2020-12") {
			return nil, errx.Validation("schema must use JSON Schema draft 2020-12")
		}
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseLoader(refuse{})
	if err = c.AddResource(resource, doc); err != nil {
		return nil, errx.Validation("invalid schema")
	}
	compiled, err := c.Compile(resource)
	if err != nil {
		return nil, errx.Validation("invalid schema: " + trim(err.Error()))
	}
	return compiled, nil
}

// Check compiles a schema; references outside it are refused.
func (Validator) Check(schema json.RawMessage) error {
	_, err := compile(schema)
	return err
}

// Validate checks a profile against a schema; the error names the first
// failing locations.
func (Validator) Validate(schema, profile json.RawMessage) error {
	compiled, err := compile(schema)
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(profile))
	if err != nil {
		return errx.Validation("profile must be valid JSON")
	}
	err = compiled.Validate(doc)
	if err == nil {
		return nil
	}
	var invalid *jsonschema.ValidationError
	if !errors.As(err, &invalid) {
		return errx.Validation("profile does not match the user schema")
	}
	out := errx.New("profile does not match the user schema: "+describe(invalid), errx.TypeValidation)
	out.Code = "PROFILE_SCHEMA"
	return out
}

// describe lists the leaf errors as "location: message".
func describe(invalid *jsonschema.ValidationError) string {
	var leaves []string
	var walk func(unit jsonschema.OutputUnit)
	walk = func(unit jsonschema.OutputUnit) {
		if unit.Error != nil && len(unit.Errors) == 0 {
			location := unit.InstanceLocation
			if location == "" {
				location = "/"
			}
			leaves = append(leaves, location+": "+unit.Error.String())
		}
		for _, child := range unit.Errors {
			walk(child)
		}
	}
	walk(*invalid.BasicOutput())
	sort.Strings(leaves)
	if len(leaves) > 3 {
		leaves = append(leaves[:3], "…")
	}
	return trim(strings.Join(leaves, "; "))
}

func trim(message string) string {
	message = strings.ReplaceAll(message, resource, "schema")
	if len(message) > 300 {
		message = message[:300] + "…"
	}
	return message
}
