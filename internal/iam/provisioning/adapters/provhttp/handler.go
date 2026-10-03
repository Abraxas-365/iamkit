package provhttp

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimEnterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
const scimListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
const scimContentType = "application/scim+json; charset=utf-8"

type scimEnterprise struct {
	Manager *scimManager `json:"manager,omitempty"`
}
type scimManager struct {
	Value string `json:"value"`
}

// UnmarshalJSON accepts the manager as `{"value":"id"}` or a bare `"id"`.
func (m *scimManager) UnmarshalJSON(raw []byte) error {
	var id string
	if err := json.Unmarshal(raw, &id); err == nil {
		m.Value = id
		return nil
	}
	var ref struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &ref); err != nil {
		return err
	}
	m.Value = ref.Value
	return nil
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary"`
}
type scimPhone struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// mobile returns the phoneNumbers[type eq "mobile"] value ("" none).
func mobile(list []scimPhone) string {
	for _, p := range list {
		if strings.EqualFold(p.Type, "mobile") {
			return strings.TrimSpace(p.Value)
		}
	}
	return ""
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}
type scimName struct {
	Formatted string `json:"formatted,omitempty"`
	Given     string `json:"givenName,omitempty"`
	Family    string `json:"familyName,omitempty"`
}
type scimUser struct {
	Enterprise  *scimEnterprise `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id,omitempty"`
	ExternalID  string          `json:"externalId,omitempty"`
	UserName    string          `json:"userName"`
	DisplayName string          `json:"displayName,omitempty"`
	Name        *scimName       `json:"name,omitempty"`
	Active      *bool           `json:"active,omitempty"`
	Emails      []scimEmail     `json:"emails,omitempty"`
	// PhoneNumbers carries the mobile number when the connection maps it.
	PhoneNumbers []scimPhone `json:"phoneNumbers,omitempty"`
	Meta         *scimMeta   `json:"meta,omitempty"`
}

// scimInput is the inbound resource; active uses parseBool so Entra's
// "True"/"False" strings are accepted.
type scimInput struct {
	scimUser
	Active json.RawMessage `json:"active,omitempty"`
}

func dto(c *fiber.Ctx, u provisioning.User) scimUser {
	active := u.Active
	out := scimUser{
		Schemas: []string{scimUserSchema}, ID: u.ID.String(),
		UserName: u.Email, DisplayName: u.Name, Name: &scimName{Formatted: u.Name}, Active: &active,
		Emails: []scimEmail{{Value: u.Email, Type: "work", Primary: true}},
		Meta:   &scimMeta{ResourceType: "User", Location: c.BaseURL() + "/scim/v2/Users/" + u.ID.String()},
	}
	// A derived anchor is IAMKit's own key, not the directory's externalId.
	if u.ExternalSource != provisioning.AnchorDerived {
		out.ExternalID = u.External
	}
	if !u.Created.IsZero() {
		out.Meta.Created = u.Created.UTC().Format(time.RFC3339)
		out.Meta.LastModified = u.Modified.UTC().Format(time.RFC3339)
	}
	for _, alias := range u.Aliases {
		out.Emails = append(out.Emails, scimEmail{Value: alias.Value, Type: alias.Type})
	}
	if u.Phone != "" {
		out.PhoneNumbers = []scimPhone{{Value: u.Phone, Type: "mobile", Primary: true}}
	}
	if u.Manager != "" {
		out.Enterprise = &scimEnterprise{Manager: &scimManager{Value: u.Manager}}
		out.Schemas = append(out.Schemas, scimEnterpriseSchema)
	}
	return out
}

// normalize fills userName/displayName from emails/name when absent.
func normalize(input *scimInput) {
	if input.UserName == "" {
		for _, email := range input.Emails {
			if input.UserName == "" || email.Primary {
				input.UserName = email.Value
			}
		}
	}
	if input.DisplayName == "" && input.Name != nil {
		input.DisplayName = strings.TrimSpace(input.Name.Formatted)
		if input.DisplayName == "" {
			input.DisplayName = strings.TrimSpace(input.Name.Given + " " + input.Name.Family)
		}
	}
}

// aliases returns emails[] as domain aliases; the primary is filtered out by
// the service.
func (input scimInput) aliases() []provisioning.Email {
	out := make([]provisioning.Email, 0, len(input.Emails))
	for _, e := range input.Emails {
		if v := strings.TrimSpace(e.Value); v != "" {
			out = append(out, provisioning.Email{Value: v, Type: e.Type})
		}
	}
	return out
}

func (input scimInput) manager() *string {
	if input.Enterprise == nil || input.Enterprise.Manager == nil {
		return nil
	}
	v := strings.TrimSpace(input.Enterprise.Manager.Value)
	return &v
}

// active returns nil when absent, else the parsed boolean.
func (input scimInput) active() (*bool, error) {
	if len(input.Active) == 0 || string(input.Active) == "null" {
		return nil, nil
	}
	v, err := parseBool(input.Active)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

type Handler struct {
	commands provisioning.Commands
	queries  provisioning.Queries
	groups   *Groups
}

func New(commands provisioning.Commands, queries provisioning.Queries, groups *Groups) *Handler {
	return &Handler{commands, queries, groups}
}
func principal(c *fiber.Ctx) provisioning.Principal {
	return c.Locals("provisioner").(provisioning.Principal)
}
func send(c *fiber.Ctx, status int, v any) error {
	return c.Status(status).JSON(v, scimContentType)
}

// projected honours ?attributes= / ?excludedAttributes= on a returned resource.
func projected(c *fiber.Ctx, core string, resource any) any {
	return project(c.Query("attributes"), c.Query("excludedAttributes"), core, resource)
}
func parse(c *fiber.Ctx, v any) error {
	if err := json.Unmarshal(c.Body(), v); err != nil {
		return scimError("invalid request body", scimInvalidSyntax)
	}
	return nil
}
func scimFailure(c *fiber.Ctx, status int, message, scimType string) error {
	if status >= 500 {
		message, scimType = "internal server error", ""
	}
	body := fiber.Map{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": strconv.Itoa(status), "detail": message}
	if scimType != "" {
		body["scimType"] = scimType
	}
	return send(c, status, body)
}

// credential extracts the provisioning secret. Directories send it as
// `Authorization: Bearer` (RFC 7644 §2); X-API-Key is kept for compatibility.
// When both are present they must agree.
func credential(c *fiber.Ctx) string {
	bearer := ""
	if scheme, token, ok := strings.Cut(strings.TrimSpace(c.Get("Authorization")), " "); ok && strings.EqualFold(scheme, "Bearer") {
		bearer = strings.TrimSpace(token)
	}
	key := strings.TrimSpace(c.Get("X-API-Key"))
	switch {
	case bearer != "" && key != "" && bearer != key:
		return ""
	case bearer != "":
		return bearer
	default:
		return key
	}
}
func (h *Handler) authenticate(c *fiber.Ctx) error {
	key := credential(c)
	if key == "" {
		return scimFailure(c, 401, "invalid credential", "")
	}
	p, err := h.commands.Authenticate(c.UserContext(), key)
	if errx.IsServerError(err) {
		return scimFailure(c, 500, "", "")
	}
	if err != nil {
		return scimFailure(c, 401, "invalid credential", "")
	}
	c.Locals("provisioner", p)
	c.Set("Cache-Control", "no-store")
	if err = c.Next(); err != nil {
		var custom *errx.Error
		if errx.As(err, &custom) && custom != nil {
			scimType, _ := custom.Details["scimType"].(string)
			if scimType == "" && custom.Type == errx.TypeConflict {
				scimType = scimUniqueness
			}
			return scimFailure(c, custom.HTTPStatus, custom.Message, scimType)
		}
		var routing *fiber.Error
		if errx.As(err, &routing) && routing != nil && routing.Code < 500 {
			return scimFailure(c, routing.Code, "resource not supported", "")
		}
		return scimFailure(c, 500, "internal server error", "")
	}
	return nil
}
func (h *Handler) Register(app *fiber.App) {
	r := app.Group("/scim/v2", h.authenticate)
	r.Get("/ServiceProviderConfig", func(c *fiber.Ctx) error {
		return send(c, 200, fiber.Map{
			"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"patch":          fiber.Map{"supported": true},
			"bulk":           fiber.Map{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":         fiber.Map{"supported": true, "maxResults": 100},
			"sort":           fiber.Map{"supported": false},
			"changePassword": fiber.Map{"supported": false},
			"etag":           fiber.Map{"supported": false},
			"authenticationSchemes": []fiber.Map{{
				"type": "oauthbearertoken", "name": "Bearer token", "primary": true,
				"description": "Provisioning credential sent as Authorization: Bearer (X-API-Key is also accepted)",
			}},
			"meta": fiber.Map{"resourceType": "ServiceProviderConfig", "location": c.BaseURL() + "/scim/v2/ServiceProviderConfig"},
		})
	})
	r.Get("/ResourceTypes", func(c *fiber.Ctx) error {
		types := []fiber.Map{userResourceType(), groupResourceType()}
		return send(c, 200, fiber.Map{"schemas": []string{scimListSchema}, "totalResults": len(types), "itemsPerPage": len(types), "startIndex": 1, "Resources": types})
	})
	r.Get("/Schemas", scimSchemas)
	r.Get("/Schemas/:id", scimSchema)
	r.Get("/ResourceTypes/:id", scimResourceType)
	r.Get("/Users", h.list)
	r.Post("/Users", h.create)
	r.Get("/Users/:id", h.get)
	r.Put("/Users/:id", h.replace)
	r.Patch("/Users/:id", h.patch)
	r.Delete("/Users/:id", h.remove)
	if h.groups != nil {
		h.groups.register(r)
	}
}
func userID(c *fiber.Ctx) (identity.UserID, error) {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return id, errx.NotFound("user not found")
	}
	return id, nil
}
func (h *Handler) get(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	u, err := h.queries.Find(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return send(c, 200, projected(c, scimUserSchema, dto(c, u)))
}
func (h *Handler) list(c *fiber.Ctx) error {
	f := provisioning.Filter{Start: c.QueryInt("startIndex", 1), Count: c.QueryInt("count", provisioning.MaxResults)}.Clamped()
	if filter := c.Query("filter"); filter != "" {
		field, value, err := parseFilter(filter)
		if err != nil {
			return err
		}
		f.Field, f.Value = field, value
	}
	rows, total, err := h.queries.List(c.UserContext(), principal(c), f)
	if err != nil {
		return err
	}
	resources := make([]any, 0, len(rows))
	for _, u := range rows {
		resources = append(resources, projected(c, scimUserSchema, dto(c, u)))
	}
	return send(c, 200, fiber.Map{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": f.Start, "itemsPerPage": len(resources), "Resources": resources})
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input scimInput
	if err := parse(c, &input); err != nil {
		return err
	}
	normalize(&input)
	active, err := input.active()
	if err != nil {
		return err
	}
	u := provisioning.User{Email: input.UserName, Name: input.DisplayName, External: strings.TrimSpace(input.ExternalID), Aliases: input.aliases(), Phone: mobile(input.PhoneNumbers), Active: true}
	if active != nil {
		u.Active = *active
	}
	if m := input.manager(); m != nil {
		u.Manager = *m
	}
	out, err := h.commands.Create(c.UserContext(), principal(c), u)
	if err != nil {
		return err
	}
	resp := dto(c, out)
	c.Set("Location", resp.Meta.Location)
	return send(c, 201, resp)
}
func (h *Handler) replace(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	var input scimInput
	if err := parse(c, &input); err != nil {
		return err
	}
	normalize(&input)
	old, err := h.queries.Find(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	// PUT is a full replace keyed by the resource id: userName may change
	// (rename), externalId may upgrade a derived anchor, emails[] becomes the
	// directory-managed alias set.
	update := provisioning.Update{}
	if userName := strings.TrimSpace(input.UserName); userName == "" {
		return scimError("userName is required", scimInvalidValue)
	} else if !strings.EqualFold(userName, old.Email) {
		update.Email = &userName
	}
	if external := strings.TrimSpace(input.ExternalID); external != "" && external != old.External {
		update.External = &external
	}
	aliases := input.aliases()
	update.Aliases = &aliases
	phone := mobile(input.PhoneNumbers) // a full replace without one clears it
	update.Phone = &phone
	name := strings.TrimSpace(input.DisplayName)
	if name == "" {
		name = old.Email
	}
	active, err := input.active()
	if err != nil {
		return err
	}
	if active == nil {
		t := true
		active = &t
	}
	update.Name, update.Active, update.Manager = &name, active, input.manager()
	return h.update(c, id, update)
}
func (h *Handler) patch(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	var input struct {
		Operations []patchOp `json:"Operations"`
	}
	if err := parse(c, &input); err != nil {
		return err
	}
	// PATCH is read-modify-write (emails[] edits apply to the current alias
	// set): the update is conditional on the version read, retried when a
	// concurrent request got there first.
	for attempt := 0; ; attempt++ {
		old, err := h.queries.Find(c.UserContext(), principal(c), id)
		if err != nil {
			return err
		}
		update, err := applyPatch(old, input.Operations)
		if err != nil {
			return err
		}
		update.IfVersion = &old.Version
		out, err := h.commands.Update(c.UserContext(), principal(c), id, update)
		if errors.Is(err, provisioning.ErrStale) && attempt < 3 {
			continue
		}
		if errors.Is(err, provisioning.ErrStale) {
			return errx.Conflict("resource was modified concurrently; retry")
		}
		if err != nil {
			return err
		}
		return send(c, 200, dto(c, out))
	}
}
func (h *Handler) update(c *fiber.Ctx, id identity.UserID, input provisioning.Update) error {
	out, err := h.commands.Update(c.UserContext(), principal(c), id, input)
	if err != nil {
		return err
	}
	return send(c, 200, dto(c, out))
}

// remove deprovisions the identity from this connection: the membership is
// deactivated and the resource answers 404 afterwards. The underlying user is
// kept (it may exist in other organizations); creating it again reactivates it.
func (h *Handler) remove(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	if err := h.commands.Delete(c.UserContext(), principal(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
