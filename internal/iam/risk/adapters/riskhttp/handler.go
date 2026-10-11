// Package riskhttp serves bot protection and risk signals: the
// environment's CAPTCHA (…/captcha), risk policy (…/risk-policy),
// restrictions (…/risk-restrictions), the sign-in attempt log
// (…/sign-in-attempts, …/users/:id/devices) and GeoIP status
// (…/risk/status) on management and /api/v1, plus the public
// GET /identity/v1/captcha/:environment a sign-in UI reads.
package riskhttp

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

// TestsPerMinute bounds CAPTCHA tests per environment and address.
const TestsPerMinute = 5

// Handler serves an environment's security settings to operators.
type Handler struct {
	captcha  risk.CaptchaCommands
	captchas risk.CaptchaQueries
	policy   risk.PolicyCommands
	policies risk.PolicyQueries
	attempts risk.AttemptQueries
	actor    func(*fiber.Ctx) string
	limit    fiber.Handler
}

// Deps are the use cases the handler serves.
type Deps struct {
	Captcha  risk.CaptchaCommands
	Captchas risk.CaptchaQueries
	Policy   risk.PolicyCommands
	Policies risk.PolicyQueries
	Attempts risk.AttemptQueries
}

func New(d Deps, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{captcha: d.Captcha, captchas: d.Captchas, policy: d.Policy, policies: d.Policies, attempts: d.Attempts, actor: actor,
		limit: limiter.New(limiter.Config{
			Max: TestsPerMinute, Expiration: time.Minute,
			KeyGenerator: func(c *fiber.Ctx) string { return c.Params("environment") + "|" + c.IP() },
			LimitReached: func(*fiber.Ctx) error { return errx.TooManyRequests("too many CAPTCHA tests; wait a minute") },
		})}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject); the rate limit is shared.
func (h *Handler) WithActor(actor func(*fiber.Ctx) string) *Handler {
	c := *h
	c.actor = actor
	return &c
}

// Register mounts every route on an environment router (management).
func (h *Handler) Register(r fiber.Router) {
	h.ReadRoutes(r)
	h.WriteRoutes(r)
}

// ReadRoutes mounts the reads, each behind guard (/api/v1:
// iam:security:read). Routes are guarded one by one: these paths sit
// directly on the environment router.
func (h *Handler) ReadRoutes(r fiber.Router, guard ...fiber.Handler) {
	g := func(h fiber.Handler) []fiber.Handler { return append(append([]fiber.Handler{}, guard...), h) }
	r.Get("/captcha", g(h.Captcha)...)
	r.Get("/risk-policy", g(h.Policy)...)
	r.Get("/risk-restrictions", g(h.Restrictions)...)
	r.Get("/sign-in-attempts", g(h.Attempts)...)
	r.Get("/sign-in-attempts/:attempt", g(h.Attempt)...)
	r.Get("/users/:id/devices", g(h.Devices)...)
	r.Get("/risk/status", g(h.Status)...)
}

// WriteRoutes mounts the writes, each behind guard (/api/v1:
// iam:security:write).
func (h *Handler) WriteRoutes(r fiber.Router, guard ...fiber.Handler) {
	g := func(hs ...fiber.Handler) []fiber.Handler { return append(append([]fiber.Handler{}, guard...), hs...) }
	r.Put("/captcha", g(h.SaveCaptcha)...)
	r.Delete("/captcha", g(h.DeleteCaptcha)...)
	r.Post("/captcha/test", g(h.limit, h.TestCaptcha)...)
	r.Put("/risk-policy", g(h.SavePolicy)...)
	r.Delete("/risk-policy", g(h.DeletePolicy)...)
	r.Post("/risk-restrictions", g(h.CreateRestriction)...)
	r.Delete("/risk-restrictions/:restriction", g(h.DeleteRestriction)...)
}

func environment(c *fiber.Ctx) (identity.EnvironmentID, error) {
	id, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return id, errx.Validation("environment must be a valid UUID")
	}
	return id, nil
}

func (h *Handler) mutation(c *fiber.Ctx) (risk.Mutation, error) {
	env, err := environment(c)
	return risk.Mutation{Environment: env, Actor: h.actor(c)}, err
}

func (h *Handler) Captcha(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	out, err := h.captchas.Captcha(c.UserContext(), env)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) SaveCaptcha(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	var input risk.CaptchaInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.captcha.SaveCaptcha(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) DeleteCaptcha(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	if err := h.captcha.DeleteCaptcha(c.UserContext(), m); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// TestCaptcha checks the stored secret with the provider (204 = accepted).
func (h *Handler) TestCaptcha(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	if err := h.captcha.TestCaptcha(c.UserContext(), env); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) Policy(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	out, err := h.policies.Policy(c.UserContext(), env)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) SavePolicy(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	var input risk.PolicyInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.policy.SavePolicy(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) DeletePolicy(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	if err := h.policy.DeletePolicy(c.UserContext(), m); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) Restrictions(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	out, err := h.policies.Restrictions(c.UserContext(), env, risk.RestrictionFilter{Kind: c.Query("kind"), Action: c.Query("action")})
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Handler) CreateRestriction(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	var input risk.NewRestriction
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.policy.CreateRestriction(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) DeleteRestriction(c *fiber.Ctx) error {
	m, err := h.mutation(c)
	if err != nil {
		return err
	}
	id, err := identity.ParseRestrictionID(c.Params("restriction"))
	if err != nil {
		return errx.NotFound("restriction not found")
	}
	if err := h.policy.DeleteRestriction(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Attempts lists sign-in attempts, newest first (?before= cursor, limit,
// user_id, ip, outcome, detection, country).
func (h *Handler) Attempts(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	f := risk.AttemptFilter{IP: c.Query("ip"), Outcome: c.Query("outcome"), Detection: c.Query("detection"), Country: c.Query("country"), Limit: c.QueryInt("limit")}
	if v := c.Query("user_id"); v != "" {
		u, err := identity.ParseUserID(v)
		if err != nil {
			return errx.Validation("user_id must be a valid UUID")
		}
		f.User = &u
	}
	if v := c.Query("before"); v != "" {
		b, err := identity.ParseSignInAttemptID(v)
		if err != nil {
			return errx.Validation("before must be an attempt id")
		}
		f.Before = &b
	}
	out, err := h.attempts.Attempts(c.UserContext(), env, f)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) Attempt(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	id, err := identity.ParseSignInAttemptID(c.Params("attempt"))
	if err != nil {
		return errx.NotFound("sign-in attempt not found")
	}
	out, err := h.attempts.Attempt(c.UserContext(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Devices lists the devices a user signed in from (newest first).
func (h *Handler) Devices(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	user, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("user not found")
	}
	out, err := h.attempts.Devices(c.UserContext(), env, user)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Handler) Status(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	out, err := h.policies.Status(c.UserContext(), env)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Public serves GET /identity/v1/captcha/:environment: what a custom
// sign-in UI renders ({enabled:false} when headless CAPTCHA is off).
type Public struct {
	captchas risk.CaptchaQueries
}

func NewPublic(captchas risk.CaptchaQueries) *Public { return &Public{captchas: captchas} }

func (p *Public) Register(r fiber.Router, limit fiber.Handler) {
	r.Get("/captcha/:environment", limit, p.Get)
}

func (p *Public) Get(c *fiber.Ctx) error {
	env, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return errx.NotFound("environment not found")
	}
	out, err := p.captchas.PublicCaptcha(c.UserContext(), env, risk.SurfaceHeadless)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "public, max-age=60")
	return c.JSON(out)
}
