package user

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Custom user data. Metadata is free-form operator data (per-key API,
// identity.ValidateMetadata limits). Profile holds end-user attributes
// checked against the environment's Schema (JSON Schema 2020-12). Schema
// properties may carry two annotations:
//
//	"x-iamkit-self":  "read" | "write" — the user sees (and edits) it
//	                  through /identity/v1/me/profile
//	"x-iamkit-claim": "<name>"          — released under that name in ID
//	                  tokens and UserInfo when the profile scope is granted

// Audit actions of custom data changes.
const (
	ActionMetadataSet     = "user.metadata_set"
	ActionMetadataDeleted = "user.metadata_deleted"
	ActionProfileUpdated  = "user.profile_updated"
	ActionSchemaUpdated   = "user.schema_updated"
	ActionSchemaDeleted   = "user.schema_deleted"
)

// Self-service access of a schema property.
const (
	SelfRead  = "read"
	SelfWrite = "write"
)

// Schema is an environment's user profile schema; Version 0 means none is
// saved and any profile object is accepted.
type Schema struct {
	Schema    json.RawMessage `json:"schema" db:"schema"`
	Version   int             `json:"version" db:"version"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty" db:"updated_at"`
}

// SchemaSaved answers a schema save: the stored schema and how many
// existing profiles do not conform to it (they are never rewritten; their
// next write must conform).
type SchemaSaved struct {
	Schema
	NonConforming int `json:"non_conforming"`
}

// Property is one top-level schema property and its annotations.
type Property struct {
	Name  string
	Self  string // "", SelfRead or SelfWrite
	Claim string
}

// ProfileRow is a user's profile, for checking profiles against a schema.
type ProfileRow struct {
	ID      identity.UserID `db:"id"`
	Profile json.RawMessage `db:"profile"`
}

// Claim names reserved by the tokens IAMKit issues.
var reservedClaims = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "auth_time", "nonce", "acr", "amr", "azp", "at_hash", "c_hash", "sid", "act", "scope", "scp",
	"name", "email", "email_verified", "phone_number", "phone_number_verified", "picture", "preferred_username", "environment_id", "organization_id", "application_id", "resource_id", "permissions", "purpose", "oauth_client_id", "token_use", "token_type"}

var claimName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$`)

// Properties parses a schema's top-level object properties and their
// annotations; the schema must describe an object.
func Properties(raw json.RawMessage) ([]Property, error) {
	var schema struct {
		Type       any                        `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if len(bytes.TrimSpace(raw)) == 0 || json.Unmarshal(raw, &schema) != nil {
		return nil, errx.Validation("schema must be a JSON object")
	}
	if schema.Type != "object" {
		return nil, errx.Validation(`schema type must be "object"`)
	}
	out := []Property{}
	claims := map[string]bool{}
	for name, body := range schema.Properties {
		var annotations struct {
			Self  *string `json:"x-iamkit-self"`
			Claim *string `json:"x-iamkit-claim"`
		}
		if json.Unmarshal(body, &annotations) != nil {
			return nil, errx.Validation("schema property " + name + " must be an object")
		}
		p := Property{Name: name}
		if annotations.Self != nil {
			if *annotations.Self != SelfRead && *annotations.Self != SelfWrite {
				return nil, errx.Validation(`x-iamkit-self of ` + name + ` must be "read" or "write"`)
			}
			p.Self = *annotations.Self
		}
		if annotations.Claim != nil {
			claim := *annotations.Claim
			if !claimName.MatchString(claim) || slices.Contains(reservedClaims, claim) {
				return nil, errx.Validation("x-iamkit-claim of " + name + " must be an unreserved claim name")
			}
			if claims[claim] {
				return nil, errx.Validation("x-iamkit-claim " + claim + " is used twice")
			}
			claims[claim] = true
			p.Claim = claim
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Property) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	})
	return out, nil
}

// MergeProfile applies a JSON merge patch of top-level keys to a profile:
// null removes a key. Only keys in allowed are accepted when allowed is
// not nil.
func MergeProfile(current, patch json.RawMessage, allowed []string) (json.RawMessage, error) {
	object := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(current)) > 0 {
		if err := json.Unmarshal(current, &object); err != nil || object == nil {
			object = map[string]json.RawMessage{}
		}
	}
	changes := map[string]json.RawMessage{}
	if err := json.Unmarshal(patch, &changes); err != nil || changes == nil {
		return nil, errx.Validation("profile must be a JSON object")
	}
	for key, value := range changes {
		if allowed != nil && !slices.Contains(allowed, key) {
			return nil, errx.Forbidden("profile attribute " + key + " cannot be changed here")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			delete(object, key)
		} else {
			object[key] = value
		}
	}
	out, err := json.Marshal(object)
	if err != nil {
		return nil, errx.Validation("profile must be a JSON object")
	}
	if len(out) > identity.MetadataMaxSize {
		return nil, errx.Validation("profile must be at most 32 KiB")
	}
	return out, nil
}

// PickProfile keeps only the named keys of a profile.
func PickProfile(profile json.RawMessage, keys []string) map[string]json.RawMessage {
	object := map[string]json.RawMessage{}
	_ = json.Unmarshal(profile, &object)
	out := map[string]json.RawMessage{}
	for _, key := range keys {
		if value, ok := object[key]; ok {
			out[key] = value
		}
	}
	return out
}
