package provhttp

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
)

// SCIM error types (RFC 7644 §3.12) carried in errx details so the SCIM
// error writer can emit them.
const (
	scimInvalidFilter = "invalidFilter"
	scimInvalidPath   = "invalidPath"
	scimInvalidValue  = "invalidValue"
	scimInvalidSyntax = "invalidSyntax"
	scimMutability    = "mutability"
	scimUniqueness    = "uniqueness"
)

func scimError(message, scimType string) error {
	return errx.Validation(message).WithDetail("scimType", scimType)
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// filterPattern matches the single-comparison filters directories send:
// `attr eq "value"`. Attribute names and the operator are case-insensitive.
var filterPattern = regexp.MustCompile(`(?i)^\s*([a-z0-9._:\-]+)\s+eq\s+("(?:[^"\\]|\\.)*")\s*$`)

var filterFields = map[string]string{
	"username":     "userName",
	"externalid":   "externalId",
	"emails.value": "emails.value",
	"emails":       "emails.value",
	"id":           "id",
}

// parseFilter turns a SCIM filter into a domain filter field/value.
func parseFilter(raw string) (field, value string, err error) {
	m := filterPattern.FindStringSubmatch(raw)
	if m == nil {
		return "", "", scimError("unsupported filter: only `attribute eq \"value\"` is supported", scimInvalidFilter)
	}
	attr := strings.ToLower(m[1])
	attr = strings.TrimPrefix(attr, strings.ToLower(scimUserSchema)+":")
	field, ok := filterFields[attr]
	if !ok {
		return "", "", scimError("unsupported filter attribute: "+m[1], scimInvalidFilter)
	}
	if err := json.Unmarshal([]byte(m[2]), &value); err != nil {
		return "", "", scimError("invalid filter value", scimInvalidFilter)
	}
	return field, value, nil
}

// applyPatch translates SCIM PATCH operations into a domain update.
// Supported attributes: active, displayName/name.formatted, userName (rename),
// externalId (upgrade of a derived anchor), emails (aliases),
// phoneNumbers[type eq "mobile"] (stored only when the connection maps
// phones) and the enterprise manager. Attributes IAMKit does not store (name.givenName, title,
// department, addresses, …) are ignored, as directories send their full
// attribute mapping and treat any 400 as a sync failure.
func applyPatch(old provisioning.User, ops []patchOp) (provisioning.Update, error) {
	var update provisioning.Update
	state := patchState{update: &update, old: old, aliases: append([]provisioning.Email{}, old.Aliases...)}
	for _, op := range ops {
		kind := strings.ToLower(op.Op)
		if kind != "add" && kind != "replace" && kind != "remove" {
			return update, scimError("unsupported patch operation: "+op.Op, scimInvalidSyntax)
		}
		if op.Path == "" {
			if kind == "remove" {
				return update, scimError("remove requires a path", scimInvalidPath)
			}
			var values map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &values); err != nil {
				return update, scimError("patch value without path must be an object", scimInvalidValue)
			}
			// Deterministic order; the effective primary is resolved at the end.
			keys := make([]string, 0, len(values))
			for key := range values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				value := values[key]
				if err := state.apply(kind, key, value); err != nil {
					return update, err
				}
			}
			continue
		}
		if err := state.apply(kind, op.Path, op.Value); err != nil {
			return update, err
		}
	}
	if update.Email != nil && strings.EqualFold(*update.Email, old.Email) {
		update.Email = nil
	}
	if update.External != nil && *update.External == old.External {
		update.External = nil
	}
	// A rename releases the previous primary address unless the directory
	// lists it among the emails.
	if state.touched || update.Email != nil {
		primary := old.Email
		if update.Email != nil {
			primary = strings.ToLower(*update.Email)
		}
		aliases := []provisioning.Email{}
		for _, a := range state.aliases {
			if !strings.EqualFold(a.Value, primary) {
				aliases = append(aliases, a)
			}
		}
		update.Aliases = &aliases
	}
	return update, nil
}

// patchState accumulates PATCH operations; emails[] edits apply to a working
// copy of the aliases that becomes the replace-set.
type patchState struct {
	update  *provisioning.Update
	old     provisioning.User
	aliases []provisioning.Email
	touched bool
}

// emailPath matches `emails[type eq "work"]`, `emails[value eq "x"].value`,
// `emails[primary eq true].value`, …
var emailPath = regexp.MustCompile(`(?i)^emails\[\s*(type|value|primary)\s+eq\s+("(?:[^"\\]|\\.)*"|true|false)\s*\](\.value)?$`)

// mobilePath matches `phoneNumbers[type eq "mobile"]` and its `.value`.
var mobilePath = regexp.MustCompile(`(?i)^phonenumbers\[\s*type\s+eq\s+"mobile"\s*\](\.value)?$`)

func (s *patchState) apply(kind, path string, value json.RawMessage) error {
	attr := strings.ToLower(strings.TrimSpace(path))
	attr = strings.TrimPrefix(attr, strings.ToLower(scimUserSchema)+":")
	switch {
	case attr == "emails":
		return s.emails(kind, value)
	case strings.HasPrefix(attr, "emails["):
		m := emailPath.FindStringSubmatch(strings.TrimPrefix(strings.TrimSpace(path), scimUserSchema+":"))
		if m == nil {
			return nil // other value filters (e.g. `emails[type eq "work" and …]`) are not stored
		}
		var match string
		if err := json.Unmarshal([]byte(m[2]), &match); err != nil {
			match = strings.ToLower(m[2]) // true/false literal
		}
		return s.emailFilter(kind, strings.ToLower(m[1]), match, value)
	case attr == "emails.value":
		return s.emails(kind, value)
	case attr == "phonenumbers":
		return s.phones(kind, value)
	case mobilePath.MatchString(attr):
		phone := ""
		if kind != "remove" {
			v, err := stringValue(subValue(value), "phoneNumbers.value")
			if err != nil {
				return err
			}
			phone = v
		}
		s.update.Phone = &phone
		return nil
	case strings.HasPrefix(attr, "phonenumbers"):
		return nil // other phone types are not stored
	case attr == "username":
		if kind == "remove" {
			return scimError("userName cannot be removed", scimMutability)
		}
		v, err := stringValue(value, "userName")
		if err != nil {
			return err
		}
		if v != "" {
			s.update.Email = &v
		}
		return nil
	case attr == "externalid":
		if kind == "remove" {
			return scimError("externalId cannot be removed", scimMutability)
		}
		v, err := stringValue(value, "externalId")
		if err != nil {
			return err
		}
		if v != "" {
			s.update.External = &v
		}
		return nil
	}
	return applyAttribute(s.update, kind, path, value)
}

// emails handles the whole multi-valued attribute: add merges, replace resets,
// remove clears. The primary address is managed through userName.
func (s *patchState) emails(kind string, value json.RawMessage) error {
	s.touched = true
	if kind == "remove" {
		s.aliases = nil
		return nil
	}
	list, err := emailList(value)
	if err != nil {
		return err
	}
	if kind == "replace" {
		s.aliases = nil
	}
	for _, e := range list {
		s.add(e)
	}
	return nil
}

func (s *patchState) emailFilter(kind, field, match string, value json.RawMessage) error {
	if field == "primary" {
		if match != "true" || kind == "remove" {
			return nil
		}
		return s.apply("replace", "userName", subValue(value))
	}
	s.touched = true
	keep := s.aliases[:0:0]
	for _, a := range s.aliases {
		if (field == "type" && strings.EqualFold(a.Type, match)) || (field == "value" && strings.EqualFold(a.Value, match)) {
			continue // a filtered sub-attribute path is single-valued: replace it
		}
		keep = append(keep, a)
	}
	s.aliases = keep
	if kind == "remove" {
		return nil
	}
	v := subValue(value)
	address, err := stringValue(v, "emails.value")
	if err != nil {
		return err
	}
	if address == "" {
		return nil
	}
	e := provisioning.Email{Value: address, Type: "other"}
	if field == "type" {
		e.Type = match
	}
	s.add(e)
	return nil
}

// phones handles the whole phoneNumbers attribute: only the mobile entry is
// kept; replace without one and remove clear it, add without one keeps it.
func (s *patchState) phones(kind string, value json.RawMessage) error {
	phone := ""
	if kind != "remove" {
		var list []scimPhone
		if err := json.Unmarshal(value, &list); err != nil {
			var one scimPhone
			if err := json.Unmarshal(value, &one); err != nil {
				return scimError("phoneNumbers must be a list", scimInvalidValue)
			}
			list = []scimPhone{one}
		}
		phone = mobile(list)
		if phone == "" && kind == "add" {
			return nil
		}
	}
	s.update.Phone = &phone
	return nil
}

// add inserts or updates an alias. The effective primary address is removed
// from the set once all operations are applied.
func (s *patchState) add(e provisioning.Email) {
	for i, a := range s.aliases {
		if strings.EqualFold(a.Value, e.Value) {
			if e.Type != "" {
				s.aliases[i].Type = e.Type
			}
			return
		}
	}
	s.aliases = append(s.aliases, e)
}

// subValue unwraps `{"value":"x"}` element objects into `"x"`.
func subValue(value json.RawMessage) json.RawMessage {
	var element struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(value, &element); err == nil && element.Value != nil {
		return element.Value
	}
	return value
}

func stringValue(value json.RawMessage, name string) (string, error) {
	var v string
	if err := json.Unmarshal(value, &v); err != nil {
		return "", scimError(name+" must be a string", scimInvalidValue)
	}
	return strings.TrimSpace(v), nil
}

// emailList accepts an emails[] array, a single element or a bare address.
func emailList(value json.RawMessage) ([]provisioning.Email, error) {
	var list []scimEmail
	if err := json.Unmarshal(value, &list); err != nil {
		var one scimEmail
		if err := json.Unmarshal(value, &one); err != nil {
			address, err := stringValue(value, "emails")
			if err != nil {
				return nil, err
			}
			one.Value = address
		}
		list = []scimEmail{one}
	}
	out := make([]provisioning.Email, 0, len(list))
	for _, e := range list {
		if v := strings.TrimSpace(e.Value); v != "" {
			out = append(out, provisioning.Email{Value: v, Type: e.Type})
		}
	}
	return out, nil
}

func applyAttribute(update *provisioning.Update, kind, path string, value json.RawMessage) error {
	attr := strings.ToLower(strings.TrimSpace(path))
	attr = strings.TrimPrefix(attr, strings.ToLower(scimUserSchema)+":")
	enterprise := strings.ToLower(scimEnterpriseSchema)
	switch {
	case attr == enterprise:
		// Path-less object form: {"urn:…:enterprise:2.0:User": {"manager": …}}
		if kind == "remove" {
			return setManager(update, nil)
		}
		var ext map[string]json.RawMessage
		if err := json.Unmarshal(value, &ext); err != nil {
			return scimError("invalid enterprise extension", scimInvalidValue)
		}
		for key, v := range ext {
			if strings.EqualFold(key, "manager") {
				if err := setManager(update, v); err != nil {
					return err
				}
			}
		}
		return nil
	case attr == enterprise+":manager", attr == enterprise+":manager.value",
		attr == enterprise+".manager", attr == "manager", attr == "manager.value":
		if kind == "remove" {
			return setManager(update, nil)
		}
		return setManager(update, value)
	case strings.HasPrefix(attr, enterprise+":"):
		return nil // department, employeeNumber, … are not stored
	case attr == "active":
		if kind == "remove" {
			return nil
		}
		active, err := parseBool(value)
		if err != nil {
			return err
		}
		update.Active = &active
		return nil
	case attr == "displayname", attr == "name.formatted":
		if kind == "remove" {
			return nil
		}
		var name string
		if err := json.Unmarshal(value, &name); err != nil {
			return scimError(path+" must be a string", scimInvalidValue)
		}
		if name = strings.TrimSpace(name); name != "" {
			update.Name = &name
		}
		return nil
	case attr == "name":
		if kind == "remove" {
			return nil
		}
		var name scimName
		if err := json.Unmarshal(value, &name); err != nil {
			return scimError("name must be an object", scimInvalidValue)
		}
		if formatted := strings.TrimSpace(name.Formatted); formatted != "" && update.Name == nil {
			update.Name = &formatted
		}
		return nil
	case attr == "id", attr == "meta" || strings.HasPrefix(attr, "meta."), attr == "schemas":
		return nil // read-only; ignored per RFC 7644 §3.5.2
	default:
		return nil // attribute not stored by IAMKit
	}
}

// setManager accepts a manager as `"id"`, `{"value":"id"}`, null or absent (clear).
func setManager(update *provisioning.Update, value json.RawMessage) error {
	manager := ""
	value = bytes.TrimSpace(value)
	if len(value) > 0 && !bytes.Equal(value, []byte("null")) {
		if err := json.Unmarshal(value, &manager); err != nil {
			var ref struct {
				Value *string `json:"value"`
			}
			if err := json.Unmarshal(value, &ref); err != nil {
				return scimError("manager must be a user id or {\"value\": id}", scimInvalidValue)
			}
			if ref.Value != nil {
				manager = *ref.Value
			}
		}
	}
	manager = strings.TrimSpace(manager)
	update.Manager = &manager
	return nil
}

// parseBool accepts JSON booleans and the "True"/"False" strings Entra sends
// without the aadOptscim062020 flag.
func parseBool(value json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(value, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(value, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, scimError("active must be a boolean", scimInvalidValue)
}
