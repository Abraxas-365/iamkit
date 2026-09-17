package provhttp

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/gofiber/fiber/v2"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimEnterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

type scimEnterprise struct {
	Manager struct {
		Value string `json:"value"`
	} `json:"manager"`
}
type scimUser struct {
	Enterprise  *scimEnterprise `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id,omitempty"`
	ExternalID  string          `json:"externalId,omitempty"`
	UserName    string          `json:"userName"`
	DisplayName string          `json:"displayName"`
	Active      *bool           `json:"active,omitempty"`
	Emails      []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails,omitempty"`
	Name struct {
		Given  string `json:"givenName"`
		Family string `json:"familyName"`
	} `json:"name,omitempty"`
}

func dto(u provisioning.User) scimUser {
	out := scimUser{Schemas: []string{scimUserSchema}, ID: u.ID, ExternalID: u.External, UserName: u.Email, DisplayName: u.Name, Active: &u.Active}
	if u.Manager != "" {
		out.Enterprise = &scimEnterprise{}
		out.Enterprise.Manager.Value = u.Manager
		out.Schemas = append(out.Schemas, scimEnterpriseSchema)
	}
	return out
}
func normalize(input *scimUser) {
	if input.UserName == "" {
		for _, email := range input.Emails {
			if input.UserName == "" || email.Primary {
				input.UserName = email.Value
			}
		}
	}
	if input.DisplayName == "" {
		input.DisplayName = strings.TrimSpace(input.Name.Given + " " + input.Name.Family)
	}
}

type Handler struct {
	commands provisioning.Commands
	queries  provisioning.Queries
}

func New(commands provisioning.Commands, queries provisioning.Queries) *Handler {
	return &Handler{commands, queries}
}
func principal(c *fiber.Ctx) provisioning.Principal {
	return c.Locals("provisioner").(provisioning.Principal)
}
func parse(c *fiber.Ctx, v any) error {
	if err := c.BodyParser(v); err != nil {
		return errx.Validation("invalid request")
	}
	return nil
}
func scimFailure(c *fiber.Ctx, status int, message string) error {
	if status >= 500 {
		message = "internal server error"
	}
	return c.Status(status).JSON(fiber.Map{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": strconv.Itoa(status), "detail": message})
}
func (h *Handler) authenticate(c *fiber.Ctx) error {
	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return scimFailure(c, 401, "invalid credential")
	}
	p, err := h.commands.Authenticate(c.Context(), parts[1])
	if err != nil {
		return scimFailure(c, 401, "invalid credential")
	}
	c.Locals("provisioner", p)
	c.Set("Cache-Control", "no-store")
	if err = c.Next(); err != nil {
		var custom *errx.Error
		if errx.As(err, &custom) && custom != nil {
			return scimFailure(c, custom.HTTPStatus, custom.Message)
		}
		return scimFailure(c, 500, "internal server error")
	}
	return nil
}
func (h *Handler) Register(app *fiber.App) {
	r := app.Group("/scim/v2", h.authenticate)
	r.Get("/ServiceProviderConfig", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, "patch": fiber.Map{"supported": true}, "bulk": fiber.Map{"supported": false}, "filter": fiber.Map{"supported": true, "maxResults": 100}, "sort": fiber.Map{"supported": false}, "changePassword": fiber.Map{"supported": false}, "etag": fiber.Map{"supported": false}, "authenticationSchemes": []fiber.Map{{"type": "oauthbearertoken", "name": "Scoped provisioning token", "description": "Environment and organization bound credential"}}})
	})
	r.Get("/ResourceTypes", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": 1, "Resources": []fiber.Map{{"id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema, "schemaExtensions": []fiber.Map{{"schema": scimEnterpriseSchema, "required": false}}}}})
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
}
func (h *Handler) get(c *fiber.Ctx) error {
	u, err := h.queries.Find(c.Context(), principal(c), c.Params("id"))
	if err != nil {
		return err
	}
	return c.JSON(dto(u))
}
func (h *Handler) list(c *fiber.Ctx) error {
	f := provisioning.Filter{Start: c.QueryInt("startIndex", 1), Count: c.QueryInt("count", 100)}
	if filter := c.Query("filter"); filter != "" {
		parts := strings.SplitN(filter, " eq ", 2)
		if len(parts) != 2 {
			return errx.Validation("unsupported filter")
		}
		f.Field = parts[0]
		if err := json.Unmarshal([]byte(parts[1]), &f.Value); err != nil {
			return errx.Validation("invalid filter")
		}
	}
	rows, total, err := h.queries.List(c.Context(), principal(c), f)
	if err != nil {
		return err
	}
	resources := make([]scimUser, 0, len(rows))
	for _, u := range rows {
		resources = append(resources, dto(u))
	}
	return c.JSON(fiber.Map{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": total, "startIndex": f.Start, "itemsPerPage": len(resources), "Resources": resources})
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input scimUser
	if err := parse(c, &input); err != nil {
		return err
	}
	normalize(&input)
	u := provisioning.User{Email: input.UserName, Name: input.DisplayName, External: input.ExternalID, Active: true}
	if input.Active != nil {
		u.Active = *input.Active
	}
	if input.Enterprise != nil {
		u.Manager = input.Enterprise.Manager.Value
	}
	out, err := h.commands.Create(c.Context(), principal(c), u)
	if err != nil {
		return err
	}
	input.ID = out.ID
	input.UserName = out.Email
	input.DisplayName = out.Name
	input.ExternalID = out.External
	input.Active = &out.Active
	input.Schemas = []string{scimUserSchema}
	if input.Enterprise != nil {
		input.Schemas = append(input.Schemas, scimEnterpriseSchema)
	}
	c.Set("Location", "/scim/v2/Users/"+out.ID)
	return c.Status(201).JSON(input)
}
func (h *Handler) replace(c *fiber.Ctx) error {
	var input scimUser
	if err := parse(c, &input); err != nil {
		return err
	}
	normalize(&input)
	old, err := h.queries.Find(c.Context(), principal(c), c.Params("id"))
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(input.UserName), old.Email) || (input.ExternalID != "" && input.ExternalID != old.External) {
		return errx.Validation("identity identifiers are immutable")
	}
	if input.DisplayName == "" {
		input.DisplayName = old.Email
	}
	active := true
	if input.Active != nil {
		active = *input.Active
	}
	update := provisioning.Update{Name: &input.DisplayName, Active: &active}
	if input.Enterprise != nil {
		update.Manager = &input.Enterprise.Manager.Value
	}
	return h.update(c, update)
}
func (h *Handler) patch(c *fiber.Ctx) error {
	if _, err := h.queries.Find(c.Context(), principal(c), c.Params("id")); err != nil {
		return err
	}
	var input struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if err := parse(c, &input); err != nil {
		return err
	}
	var update provisioning.Update
	for _, op := range input.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			return errx.Validation("unsupported patch operation")
		}
		switch strings.ToLower(op.Path) {
		case strings.ToLower(scimEnterpriseSchema + ":manager.value"):
			var manager string
			if err := json.Unmarshal(op.Value, &manager); err != nil {
				return errx.Validation("manager value must be user ID")
			}
			update.Manager = &manager
		case strings.ToLower(scimEnterpriseSchema + ":manager"):
			var manager struct {
				Value string `json:"value"`
			}
			if err := json.Unmarshal(op.Value, &manager); err != nil {
				return errx.Validation("invalid manager")
			}
			update.Manager = &manager.Value
		case "active":
			if err := json.Unmarshal(op.Value, &update.Active); err != nil {
				return errx.Validation("active must be boolean")
			}
		case "displayname":
			if err := json.Unmarshal(op.Value, &update.Name); err != nil {
				return errx.Validation("displayName must be string")
			}
		case "":
			var values struct {
				Active     *bool           `json:"active"`
				Name       *string         `json:"displayName"`
				Enterprise *scimEnterprise `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`
			}
			if err := json.Unmarshal(op.Value, &values); err != nil {
				return errx.Validation("invalid patch value")
			}
			if values.Active != nil {
				update.Active = values.Active
			}
			if values.Name != nil {
				update.Name = values.Name
			}
			if values.Enterprise != nil {
				update.Manager = &values.Enterprise.Manager.Value
			}
		default:
			return errx.Validation("unsupported patch path")
		}
	}
	return h.update(c, update)
}
func (h *Handler) update(c *fiber.Ctx, input provisioning.Update) error {
	out, err := h.commands.Update(c.Context(), principal(c), c.Params("id"), input)
	if err != nil {
		return err
	}
	if c.Method() == "DELETE" {
		return c.SendStatus(204)
	}
	return c.JSON(dto(out))
}
func (h *Handler) remove(c *fiber.Ctx) error {
	active := false
	return h.update(c, provisioning.Update{Active: &active})
}
