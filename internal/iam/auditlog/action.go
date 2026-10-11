// Package auditlog is the app audit log: events the environment's own
// applications emit about what their users did (invoice.paid, …), kept per
// organization and readable by the customer. It is separate from IAMKit's
// own event log (package event): the events here are customer data with
// their own shape, retention and permissions, and never enter IAMKit's log.
//
// An action must be registered before events can name it. Registering
// gives the target types it accepts and optional JSON Schemas (draft
// 2020-12) for the metadata of the event, of its actor and of each target
// type; every change of those rules bumps the action's version and events
// record the version they were validated with. Events are immutable.
package auditlog

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Audited route names of action mutations (event.Classify knows them).
const (
	AuditActionCreate = "audit_log_action.create"
	AuditActionUpdate = "audit_log_action.update"
	AuditActionDelete = "audit_log_action.delete"
)

// Limits of registered actions.
const (
	// MaxActions caps the actions of an environment.
	MaxActions = 500
	// MaxTargetTypes caps the target types of one action.
	MaxTargetTypes = 20
	// MaxNameLength / MaxDescriptionLength mirror the table's CHECKs.
	MaxNameLength        = 100
	MaxDescriptionLength = 500
	// MaxTypeLength bounds a target type.
	MaxTypeLength = 40
	// MaxSchemaBytes bounds one JSON Schema.
	MaxSchemaBytes = 16 << 10
)

var (
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	typePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// ValidName reports whether s is shaped like an action name
// (dotted lowercase words, e.g. invoice.paid).
func ValidName(s string) bool { return len(s) <= MaxNameLength && namePattern.MatchString(s) }

// Mutation is an audited change of the action catalog.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// Schema holds the optional JSON Schemas of an action: Metadata for the
// event's metadata, Actor for the actor's metadata and Targets for the
// metadata of the targets of each type.
type Schema struct {
	Metadata json.RawMessage            `json:"metadata,omitempty"`
	Actor    json.RawMessage            `json:"actor,omitempty"`
	Targets  map[string]json.RawMessage `json:"targets,omitempty"`
}

func checkSchemaDocument(field string, raw json.RawMessage) error {
	if len(raw) > MaxSchemaBytes {
		return errx.Validation(field + " must be at most 16 KiB")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return errx.Validation(field + " must be a JSON Schema object")
	}
	return nil
}

// Validate checks the shape of the schemas; whether they compile is the
// SchemaValidator's to say. Target schemas need their type in targetTypes.
func (s Schema) Validate(targetTypes []string) error {
	if len(s.Metadata) > 0 {
		if err := checkSchemaDocument("schema.metadata", s.Metadata); err != nil {
			return err
		}
	}
	if len(s.Actor) > 0 {
		if err := checkSchemaDocument("schema.actor", s.Actor); err != nil {
			return err
		}
	}
	for typ, raw := range s.Targets {
		if !contains(targetTypes, typ) {
			return errx.Validation("schema.targets." + typ + " names a type that is not in target_types")
		}
		if err := checkSchemaDocument("schema.targets."+typ, raw); err != nil {
			return err
		}
	}
	return nil
}

// Documents lists the schemas that are set.
func (s Schema) Documents() []json.RawMessage {
	var out []json.RawMessage
	for _, raw := range []json.RawMessage{s.Metadata, s.Actor} {
		if len(raw) > 0 {
			out = append(out, raw)
		}
	}
	for _, raw := range s.Targets {
		out = append(out, raw)
	}
	return out
}

// Equal reports whether both hold the same schemas (formatting and key
// order aside).
func (s Schema) Equal(other Schema) bool {
	a, errA := normalizeSchema(s)
	b, errB := normalizeSchema(other)
	return errA == nil && errB == nil && reflect.DeepEqual(a, b)
}

func normalizeSchema(s Schema) (any, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out any
	return out, json.Unmarshal(raw, &out)
}

// Action is a registered action.
type Action struct {
	ID          identity.AuditActionID `json:"id"`
	Environment identity.EnvironmentID `json:"environment_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	TargetTypes []string               `json:"target_types"`
	Schema      Schema                 `json:"schema"`
	// Version starts at 1 and grows with every change of the target types
	// or schemas, the rules events are validated with.
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ActionInput registers an action.
type ActionInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TargetTypes []string `json:"target_types"`
	Schema      Schema   `json:"schema"`
}

func checkDescription(description string) error {
	if utf8.RuneCountInString(description) > MaxDescriptionLength || !utf8.ValidString(description) {
		return errx.Validation("description must be at most 500 characters")
	}
	return nil
}

func checkTargetTypes(types []string) error {
	if len(types) > MaxTargetTypes {
		return errx.Validation("target_types must name at most 20 types")
	}
	seen := map[string]bool{}
	for _, t := range types {
		if len(t) > MaxTypeLength || !typePattern.MatchString(t) {
			return errx.Validation("target_types must be lowercase words such as invoice or credit_note")
		}
		if seen[t] {
			return errx.Validation("target_types must not repeat " + t)
		}
		seen[t] = true
	}
	return nil
}

// Normalize trims the free text.
func (i ActionInput) Normalize() ActionInput {
	i.Name, i.Description = strings.TrimSpace(i.Name), strings.TrimSpace(i.Description)
	if i.TargetTypes == nil {
		i.TargetTypes = []string{}
	}
	return i
}

func (i ActionInput) Validate() error {
	if !ValidName(i.Name) {
		return errx.Validation("name must be lowercase words separated by dots, such as invoice.paid (at most 100 characters)")
	}
	if err := checkDescription(i.Description); err != nil {
		return err
	}
	if err := checkTargetTypes(i.TargetTypes); err != nil {
		return err
	}
	return i.Schema.Validate(i.TargetTypes)
}

// ActionUpdate changes an action; absent members keep their value. The
// name never changes. A given schema replaces all of the action's schemas.
type ActionUpdate struct {
	Description *string   `json:"description"`
	TargetTypes *[]string `json:"target_types"`
	Schema      *Schema   `json:"schema"`
}

// Apply returns the action with the update applied and reports whether the
// rules events are validated with changed (the version must grow).
func (u ActionUpdate) Apply(current Action) (next Action, rules bool, err error) {
	next = current
	if u.Description != nil {
		next.Description = strings.TrimSpace(*u.Description)
		if err = checkDescription(next.Description); err != nil {
			return current, false, err
		}
	}
	if u.TargetTypes != nil {
		next.TargetTypes = *u.TargetTypes
		if next.TargetTypes == nil {
			next.TargetTypes = []string{}
		}
		if err = checkTargetTypes(next.TargetTypes); err != nil {
			return current, false, err
		}
	}
	if u.Schema != nil {
		next.Schema = *u.Schema
	}
	if err = next.Schema.Validate(next.TargetTypes); err != nil {
		return current, false, err
	}
	rules = !next.Schema.Equal(current.Schema) || !reflect.DeepEqual(nonNil(next.TargetTypes), nonNil(current.TargetTypes))
	return next, rules, nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
