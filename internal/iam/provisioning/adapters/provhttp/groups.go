package provhttp

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/gofiber/fiber/v2"
)

const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"`
}
type scimGroup struct {
	Schemas     []string      `json:"schemas"`
	ID          string        `json:"id,omitempty"`
	ExternalID  string        `json:"externalId,omitempty"`
	DisplayName string        `json:"displayName"`
	Members     *[]scimMember `json:"members,omitempty"`
	Meta        *scimMeta     `json:"meta,omitempty"`
}

// Groups serves /scim/v2/Groups. It is registered by Handler.Register so it
// shares the credential middleware and SCIM error writer.
type Groups struct {
	commands provisioning.GroupCommands
	queries  provisioning.GroupQueries
}

func NewGroups(commands provisioning.GroupCommands, queries provisioning.GroupQueries) *Groups {
	return &Groups{commands, queries}
}

func (h *Groups) register(r fiber.Router) {
	r.Get("/Groups", h.list)
	r.Post("/Groups", h.create)
	r.Get("/Groups/:id", h.get)
	r.Put("/Groups/:id", h.replace)
	r.Patch("/Groups/:id", h.patch)
	r.Delete("/Groups/:id", h.remove)
}

func groupDTO(c *fiber.Ctx, g provisioning.Group) scimGroup {
	out := scimGroup{
		Schemas: []string{scimGroupSchema}, ID: g.ID.String(), ExternalID: g.External, DisplayName: g.Name,
		Meta: &scimMeta{ResourceType: "Group", Location: c.BaseURL() + "/scim/v2/Groups/" + g.ID.String()},
	}
	if !g.Created.IsZero() {
		out.Meta.Created = g.Created.UTC().Format(time.RFC3339)
		out.Meta.LastModified = g.Modified.UTC().Format(time.RFC3339)
	}
	if g.Members != nil {
		members := make([]scimMember, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, scimMember{Value: m.User.String(), Display: m.Display, Type: "User", Ref: c.BaseURL() + "/scim/v2/Users/" + m.User.String()})
		}
		out.Members = &members
	}
	return out
}

// wantMembers honours excludedAttributes=members and attributes=… lists that
// omit members; directories use both to avoid transferring large groups.
func wantMembers(c *fiber.Ctx) bool {
	has := func(list string) bool {
		for _, a := range strings.Split(list, ",") {
			a = strings.ToLower(strings.TrimSpace(a))
			a = strings.TrimPrefix(a, strings.ToLower(scimGroupSchema)+":")
			if a == "members" || strings.HasPrefix(a, "members.") {
				return true
			}
		}
		return false
	}
	if has(c.Query("excludedAttributes")) {
		return false
	}
	if attrs := c.Query("attributes"); attrs != "" {
		return has(attrs)
	}
	return true
}

func groupID(c *fiber.Ctx) (identity.GroupID, error) {
	id, err := identity.ParseGroupID(c.Params("id"))
	if err != nil {
		return id, errx.NotFound("group not found")
	}
	return id, nil
}

var groupFilterFields = map[string]string{
	"displayname": "displayName",
	"externalid":  "externalId",
	"id":          "id",
}

func parseGroupFilter(raw string) (field, value string, err error) {
	m := filterPattern.FindStringSubmatch(raw)
	if m == nil {
		return "", "", scimError("unsupported filter: only `attribute eq \"value\"` is supported", scimInvalidFilter)
	}
	attr := strings.TrimPrefix(strings.ToLower(m[1]), strings.ToLower(scimGroupSchema)+":")
	field, ok := groupFilterFields[attr]
	if !ok {
		return "", "", scimError("unsupported filter attribute: "+m[1], scimInvalidFilter)
	}
	if err := json.Unmarshal([]byte(m[2]), &value); err != nil {
		return "", "", scimError("invalid filter value", scimInvalidFilter)
	}
	return field, value, nil
}

func (h *Groups) list(c *fiber.Ctx) error {
	f := provisioning.Filter{Start: c.QueryInt("startIndex", 1), Count: c.QueryInt("count", provisioning.MaxResults)}.Clamped()
	gf := provisioning.GroupFilter{ExcludeMembers: !wantMembers(c)}
	if filter := c.Query("filter"); filter != "" {
		field, value, err := parseGroupFilter(filter)
		if err != nil {
			return err
		}
		gf.Field, gf.Value = field, value
	}
	out, err := h.queries.ListGroups(c.UserContext(), principal(c), gf, query.Pagination{Limit: f.Count, Offset: f.Start - 1})
	if err != nil {
		return err
	}
	resources := make([]any, 0, len(out.Items))
	for _, g := range out.Items {
		resources = append(resources, projected(c, scimGroupSchema, groupDTO(c, g)))
	}
	return send(c, 200, fiber.Map{"schemas": []string{scimListSchema}, "totalResults": out.Page.Total, "startIndex": f.Start, "itemsPerPage": len(resources), "Resources": resources})
}

func (h *Groups) get(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	g, err := h.queries.FindGroup(c.UserContext(), principal(c), id, wantMembers(c))
	if err != nil {
		return err
	}
	return send(c, 200, projected(c, scimGroupSchema, groupDTO(c, g)))
}

// groupInput is the inbound resource for POST and PUT.
type groupInput struct {
	ExternalID  string          `json:"externalId"`
	DisplayName string          `json:"displayName"`
	Members     json.RawMessage `json:"members"`
}

func (h *Groups) create(c *fiber.Ctx) error {
	var input groupInput
	if err := parse(c, &input); err != nil {
		return err
	}
	members, err := memberList(input.Members)
	if err != nil {
		return err
	}
	id, err := h.commands.CreateGroup(c.UserContext(), principal(c), provisioning.GroupInput{Name: input.DisplayName, External: input.ExternalID, Members: members})
	if err != nil {
		return err
	}
	g, err := h.queries.FindGroup(c.UserContext(), principal(c), id, true)
	if err != nil {
		return err
	}
	resp := groupDTO(c, g)
	c.Set("Location", resp.Meta.Location)
	return send(c, 201, resp)
}

// replace is a full PUT: displayName and the member set are replaced;
// externalId changes only when supplied.
func (h *Groups) replace(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	var input groupInput
	if err := parse(c, &input); err != nil {
		return err
	}
	members, err := memberList(input.Members)
	if err != nil {
		return err
	}
	external := input.ExternalID
	update := provisioning.GroupUpdate{Name: &input.DisplayName, External: &external, Members: &members}
	if err := h.commands.UpdateGroup(c.UserContext(), principal(c), id, update); err != nil {
		return err
	}
	return h.get(c)
}

func (h *Groups) patch(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	var input struct {
		Operations []patchOp `json:"Operations"`
	}
	if err := parse(c, &input); err != nil {
		return err
	}
	update, err := applyGroupPatch(input.Operations)
	if err != nil {
		return err
	}
	if update.Empty() {
		// Still 404 for unknown groups.
		if _, err := h.queries.FindGroup(c.UserContext(), principal(c), id, false); err != nil {
			return err
		}
		return c.SendStatus(204)
	}
	if err := h.commands.UpdateGroup(c.UserContext(), principal(c), id, update); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *Groups) remove(c *fiber.Ctx) error {
	id, err := groupID(c)
	if err != nil {
		return err
	}
	if err := h.commands.DeleteGroup(c.UserContext(), principal(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// memberList accepts `[{"value":"id"}, …]`, a single element, or null.
func memberList(raw json.RawMessage) ([]identity.UserID, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return []identity.UserID{}, nil
	}
	var list []scimMember
	if err := json.Unmarshal(raw, &list); err != nil {
		var one scimMember
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, scimError("members must be a list of {\"value\": id}", scimInvalidValue)
		}
		list = []scimMember{one}
	}
	out := make([]identity.UserID, 0, len(list))
	for _, m := range list {
		id, err := memberID(m.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func memberID(raw string) (identity.UserID, error) {
	id, err := identity.ParseUserID(strings.TrimSpace(raw))
	if err != nil {
		return id, scimError("member value must be a user id", scimInvalidValue)
	}
	return id, nil
}

// groupPatch folds PATCH operations, in order, into one net change: a member
// set replacement (replace/remove-all) plus disjoint add and remove sets.
type groupPatch struct {
	update  provisioning.GroupUpdate
	replace map[identity.UserID]bool
	order   []identity.UserID
	add     map[identity.UserID]bool
	del     map[identity.UserID]bool
}

func (s *groupPatch) addMember(id identity.UserID) {
	s.order = append(s.order, id)
	if s.replace != nil {
		s.replace[id] = true
		return
	}
	s.add[id], s.del[id] = true, false
}

func (s *groupPatch) removeMember(id identity.UserID) {
	if s.replace != nil {
		delete(s.replace, id)
		return
	}
	s.del[id], s.add[id] = true, false
}

func (s *groupPatch) resetMembers(ids []identity.UserID) {
	s.replace = map[identity.UserID]bool{}
	s.add, s.del = map[identity.UserID]bool{}, map[identity.UserID]bool{}
	for _, id := range ids {
		s.addMember(id)
	}
}

// memberPath matches `members[value eq "id"]`, the form Entra and Okta use to
// remove a single member.
var memberPath = regexp.MustCompile(`(?i)^members\[\s*value\s+eq\s+("(?:[^"\\]|\\.)*")\s*\]$`)

// applyGroupPatch supports displayName, externalId and members with the forms
// Entra ID and Okta send; unknown attributes are ignored.
func applyGroupPatch(ops []patchOp) (provisioning.GroupUpdate, error) {
	s := &groupPatch{add: map[identity.UserID]bool{}, del: map[identity.UserID]bool{}}
	for _, op := range ops {
		kind := strings.ToLower(op.Op)
		if kind != "add" && kind != "replace" && kind != "remove" {
			return s.update, scimError("unsupported patch operation: "+op.Op, scimInvalidSyntax)
		}
		if op.Path == "" {
			if kind == "remove" {
				return s.update, scimError("remove requires a path", scimInvalidPath)
			}
			var values map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &values); err != nil {
				return s.update, scimError("patch value without path must be an object", scimInvalidValue)
			}
			// displayName/externalId before members; members last is stable.
			for _, key := range []string{"displayName", "externalId", "members"} {
				for k, v := range values {
					if strings.EqualFold(k, key) {
						if err := s.apply(kind, key, v); err != nil {
							return s.update, err
						}
					}
				}
			}
			continue
		}
		if err := s.apply(kind, op.Path, op.Value); err != nil {
			return s.update, err
		}
	}
	if s.replace != nil {
		members := []identity.UserID{}
		for _, id := range s.order {
			if s.replace[id] {
				members = append(members, id)
				delete(s.replace, id)
			}
		}
		s.update.Members = &members
	}
	for _, id := range s.order {
		if s.add[id] {
			s.update.Add = append(s.update.Add, id)
			s.add[id] = false
		}
	}
	for id, removed := range s.del {
		if removed {
			s.update.Remove = append(s.update.Remove, id)
		}
	}
	return s.update, nil
}

func (s *groupPatch) apply(kind, path string, value json.RawMessage) error {
	trimmed := strings.TrimSpace(path)
	if prefix := scimGroupSchema + ":"; len(trimmed) > len(prefix) && strings.EqualFold(trimmed[:len(prefix)], prefix) {
		trimmed = trimmed[len(prefix):]
	}
	attr := strings.ToLower(trimmed)
	switch {
	case attr == "displayname":
		if kind == "remove" {
			return scimError("displayName cannot be removed", scimMutability)
		}
		v, err := stringValue(value, "displayName")
		if err != nil {
			return err
		}
		s.update.Name = &v
	case attr == "externalid":
		if kind == "remove" {
			return nil
		}
		v, err := stringValue(value, "externalId")
		if err != nil {
			return err
		}
		s.update.External = &v
	case attr == "members":
		switch kind {
		case "remove":
			ids, err := memberList(value)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				s.resetMembers(nil) // remove without value clears the group
			}
			for _, id := range ids {
				s.removeMember(id)
			}
		case "replace":
			ids, err := memberList(value)
			if err != nil {
				return err
			}
			s.resetMembers(ids)
		default:
			ids, err := memberList(value)
			if err != nil {
				return err
			}
			for _, id := range ids {
				s.addMember(id)
			}
		}
	case strings.HasPrefix(attr, "members["):
		m := memberPath.FindStringSubmatch(trimmed)
		if m == nil {
			return scimError("unsupported members filter: "+path, scimInvalidPath)
		}
		var raw string
		if err := json.Unmarshal([]byte(m[1]), &raw); err != nil {
			return scimError("invalid members filter value", scimInvalidPath)
		}
		id, err := memberID(raw)
		if err != nil {
			return err
		}
		if kind == "remove" {
			s.removeMember(id)
		} else {
			s.addMember(id)
		}
	default:
		// id, meta, schemas and unknown attributes are ignored (RFC 7644 §3.5.2).
	}
	return nil
}

func groupResourceType() fiber.Map {
	return fiber.Map{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema,
		"meta": fiber.Map{"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/Group"},
	}
}

func groupSchemaDefinition(attr func(name, kind, mutability string, required bool) fiber.Map) fiber.Map {
	displayName := attr("displayName", "string", "readWrite", true)
	displayName["uniqueness"] = "server"
	externalID := attr("externalId", "string", "readWrite", false)
	externalID["caseExact"] = true
	value := attr("value", "string", "immutable", false)
	value["caseExact"] = true
	members := attr("members", "complex", "readWrite", false)
	members["multiValued"] = true
	members["subAttributes"] = []fiber.Map{value, attr("display", "string", "readOnly", false), attr("type", "string", "immutable", false)}
	return fiber.Map{"schemas": []string{scimSchemaSchema}, "id": scimGroupSchema, "name": "Group", "description": "Group of provisioned users",
		"meta":       fiber.Map{"resourceType": "Schema", "location": "/scim/v2/Schemas/" + scimGroupSchema},
		"attributes": []fiber.Map{displayName, externalID, members}}
}
