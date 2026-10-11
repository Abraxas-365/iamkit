// Package apikeyhttp serves API keys: the operator surface
// (…/environments/:environment/api-keys, /api-key-policy and the machine
// user routes under /users/:id/api-keys, management and /api/v1) and the
// self-service surface (/identity/v1/me/api-keys).
package apikeyhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Handler serves the environment's API keys to operators.
type Handler struct {
	commands apikey.Commands
	queries  apikey.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands apikey.Commands, queries apikey.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, actor: actor}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *Handler) WithActor(actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: h.commands, queries: h.queries, actor: actor}
}

// Register mounts the routes on an environment router (management).
func (h *Handler) Register(r fiber.Router) {
	h.KeyRoutes(r.Group("/api-keys"))
	h.PolicyRoutes(r.Group("/api-key-policy"))
	h.UserRoutes(r.Group("/users/:id/api-keys"))
}

// KeyRoutes mounts /api-keys (the /api/v1 group carries its permission).
func (h *Handler) KeyRoutes(r fiber.Router) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Get("/:key", h.Find)
	r.Delete("/:key", h.Revoke)
}

// PolicyRoutes mounts /api-key-policy.
func (h *Handler) PolicyRoutes(r fiber.Router) {
	r.Get("/", h.Policy)
	r.Put("/", h.SavePolicy)
}

// UserRoutes mounts /users/:id/api-keys.
func (h *Handler) UserRoutes(r fiber.Router) {
	r.Get("/", h.ListUser)
	r.Post("/", h.CreateUser)
	r.Delete("/:key", h.RevokeUser)
}

func environment(c *fiber.Ctx) (identity.EnvironmentID, error) {
	id, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return id, errx.Validation("environment must be a valid UUID")
	}
	return id, nil
}

func keyID(c *fiber.Ctx) (identity.APIKeyID, error) {
	id, err := identity.ParseAPIKeyID(c.Params("key"))
	if err != nil {
		return id, errx.NotFound("API key not found")
	}
	return id, nil
}

func userID(c *fiber.Ctx) (identity.UserID, error) {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return id, errx.NotFound("user not found")
	}
	return id, nil
}

// Filter reads the listing filters every API key surface shares
// (owner_type, organization_id, user_id, resource_id, state).
func Filter(c *fiber.Ctx) (apikey.Filter, error) {
	f := apikey.Filter{OwnerType: apikey.OwnerKind(c.Query("owner_type")), State: c.Query("state")}
	var err error
	if v := c.Query("organization_id"); v != "" {
		if f.Organization, err = identity.ParseOrganizationID(v); err != nil {
			return f, errx.Validation("organization_id must be a valid UUID")
		}
	}
	if v := c.Query("user_id"); v != "" {
		if f.User, err = identity.ParseUserID(v); err != nil {
			return f, errx.Validation("user_id must be a valid UUID")
		}
	}
	if v := c.Query("resource_id"); v != "" {
		if f.Resource, err = identity.ParseResourceID(v); err != nil {
			return f, errx.Validation("resource_id must be a valid UUID")
		}
	}
	return f, nil
}

func (h *Handler) List(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	filter, err := Filter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.List(c.UserContext(), apikey.EnvironmentScope(env), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) Find(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	id, err := keyID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Find(c.UserContext(), apikey.EnvironmentScope(env), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Create issues an organization API key (operators name the organization in
// the body; there is no granter check).
func (h *Handler) Create(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	var input apikey.NewAPIKey
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	input.Owner = apikey.Owner{Type: apikey.OwnerOrganization}
	return h.issue(c, env, input)
}

func (h *Handler) issue(c *fiber.Ctx, env identity.EnvironmentID, input apikey.NewAPIKey) error {
	m := apikey.Mutation{Scope: apikey.EnvironmentScope(env), Actor: h.actor(c)}
	out, err := h.commands.Create(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) revoke(c *fiber.Ctx, env identity.EnvironmentID, id identity.APIKeyID) error {
	m := apikey.Mutation{Scope: apikey.EnvironmentScope(env), Actor: h.actor(c)}
	if err := h.commands.Revoke(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) Revoke(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	id, err := keyID(c)
	if err != nil {
		return err
	}
	return h.revoke(c, env, id)
}

func (h *Handler) Policy(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Policy(c.UserContext(), env)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) SavePolicy(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	var input apikey.Policy
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	m := apikey.Mutation{Scope: apikey.EnvironmentScope(env), Actor: h.actor(c)}
	out, err := h.commands.SavePolicy(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// ListUser lists the keys of one user, any kind.
func (h *Handler) ListUser(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	user, err := userID(c)
	if err != nil {
		return err
	}
	filter, err := Filter(c)
	if err != nil {
		return err
	}
	filter.User = user
	out, err := h.queries.List(c.UserContext(), apikey.EnvironmentScope(env), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// CreateUser issues a machine key for a machine user.
func (h *Handler) CreateUser(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	user, err := userID(c)
	if err != nil {
		return err
	}
	var input apikey.NewAPIKey
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	input.Owner = apikey.Owner{Type: apikey.OwnerMachine, User: user}
	return h.issue(c, env, input)
}

// RevokeUser revokes a key of the user (404 when the key is another's).
func (h *Handler) RevokeUser(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	user, err := userID(c)
	if err != nil {
		return err
	}
	id, err := keyID(c)
	if err != nil {
		return err
	}
	found, err := h.queries.Find(c.UserContext(), apikey.EnvironmentScope(env), id)
	if err != nil {
		return err
	}
	if found.Owner.User != user {
		return errx.NotFound("API key not found")
	}
	return h.revoke(c, env, id)
}
