package hostedhttp

import (
	"encoding/base64"
	"html/template"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"rsc.io/qr"
)

func (h *Handler) mutation(c *fiber.Ctx) hosted.Mutation {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return hosted.Mutation{Environment: env, Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}

func client(c *fiber.Ctx) (identity.ClientID, error) {
	id, err := identity.ParseClientID(c.Params("client"))
	if err != nil {
		return id, errx.Validation("invalid client id")
	}
	return id, nil
}

func (h *Handler) clientStyles(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	out, err := h.queries.ListClientSettings(c.Context(), env, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) clientStyle(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	id, err := client(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ClientSettings(c.Context(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) saveClientStyle(c *fiber.Ctx) error {
	id, err := client(c)
	if err != nil {
		return err
	}
	var input hosted.Settings
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SaveClientSettings(c.Context(), h.mutation(c), id, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteClientStyle(c *fiber.Ctx) error {
	id, err := client(c)
	if err != nil {
		return err
	}
	if err = h.commands.DeleteClientSettings(c.Context(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Preview is a hosted page rendered with sample data, for the console to
// show in a sandboxed frame.
type Preview struct {
	HTML string `json:"html"`
}

// savedPreview renders a page with the saved style of ?client= (or the
// environment default).
func (h *Handler) savedPreview(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	settings, err := h.queries.Settings(c.Context(), env)
	if err != nil {
		return err
	}
	if raw := c.Query("client"); raw != "" {
		id, err := identity.ParseClientID(raw)
		if err != nil {
			return errx.Validation("invalid client id")
		}
		own, err := h.queries.ClientSettings(c.Context(), env, id)
		var e *errx.Error
		switch {
		case err == nil:
			settings = own
		case !(errx.As(err, &e) && e.Type == errx.TypeNotFound):
			return err
		}
	}
	return preview(c, settings, c.Query("page"), c.Query("scheme"))
}

// draftPreview renders a page with an unsaved style.
func (h *Handler) draftPreview(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	var input struct {
		Page     string          `json:"page"`
		Scheme   string          `json:"scheme"`
		Settings hosted.Settings `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	settings, err := h.queries.Draft(c.Context(), env, input.Settings)
	if err != nil {
		return err
	}
	return preview(c, settings, input.Page, input.Scheme)
}

func preview(c *fiber.Ctx, settings hosted.Settings, page, scheme string) error {
	if page == "" {
		page = "identify"
	}
	v, ok := sample(page)
	if !ok {
		return errx.Validation("page must be one of identify, password, code, reset, organization, mfa, enroll, recovery, invite, message")
	}
	if scheme != "" && scheme != hosted.ModeLight && scheme != hosted.ModeDark {
		return errx.Validation("scheme must be light or dark")
	}
	v.Brand = brandOf(settings, scheme)
	out, err := document(page, &v)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(Preview{HTML: string(out)})
}

// sample is example data for each previewable page.
func sample(page string) (view, bool) {
	const email = "jane@example.com"
	connection := identity.ConnectionID{}
	all := hosted.DefaultSignIn(identity.EnvironmentID{}, identity.ClientID{})
	switch page {
	case "identify":
		return view{Title: "Sign in", SignIn: all, Connections: []federation.ConnectionSummary{{ID: connection, Name: "Google", Provider: federation.ProviderGoogle}, {ID: connection, Name: "Microsoft", Provider: federation.ProviderMicrosoft}}}, true
	case "password":
		return view{Title: "Sign in", Email: email, SignIn: all}, true
	case "code":
		return view{Title: "Check your email", Email: email, Notice: "If the account can sign in with a code, we sent an 8-digit code to " + email + "."}, true
	case "reset":
		return view{Title: "Reset your password", Email: email, Notice: "If the account exists, we sent an 8-digit code to " + email + "."}, true
	case "organization":
		return view{Title: "Choose an organization", Subtitle: "Your account belongs to several organizations.",
			Organizations: []authentication.Organization{{Name: "Acme Inc."}, {Name: "Globex"}}}, true
	case "mfa":
		return view{Title: "Two-step verification", Subtitle: "Enter the 6-digit code from your authenticator app, or a recovery code.", Error: "That code is not valid. Try again."}, true
	case "enroll":
		v := view{Title: "Set up two-step verification", Subtitle: "Your organization requires an authenticator app. Scan the code, then enter the 6-digit code it shows.", Secret: "JBSWY3DPEHPK3PXP"}
		if code, err := qr.Encode("otpauth://totp/Example:jane@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example", qr.M); err == nil {
			code.Scale = 4
			v.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()))
		}
		return v, true
	case "recovery":
		return view{Title: "Save your recovery codes", Subtitle: "Each code signs you in once if you lose your authenticator. They will not be shown again.",
			RecoveryCodes: []string{"k7d2-9xqa", "m3p8-2rtn", "c5w1-7hve", "q9z4-6bly", "t2f6-4ngs", "x8j3-1kdm"}}, true
	case "invite":
		return view{Title: "Join Acme Inc.", Subtitle: "You were invited to join Acme Inc.", Invite: &invitation.Preview{Email: "j***@example.com", OrganizationName: "Acme Inc.", PasswordRequired: true}}, true
	case "message":
		return view{Title: "Invitation accepted", Notice: "You joined Acme Inc. You can now sign in to the application."}, true
	}
	return view{}, false
}

func (h *Handler) signIn(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	id, err := client(c)
	if err != nil {
		return err
	}
	out, err := h.queries.SignIn(c.Context(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) saveSignIn(c *fiber.Ctx) error {
	id, err := client(c)
	if err != nil {
		return err
	}
	var input hosted.SignIn
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SaveSignIn(c.Context(), h.mutation(c), id, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteSignIn(c *fiber.Ctx) error {
	id, err := client(c)
	if err != nil {
		return err
	}
	if err = h.commands.DeleteSignIn(c.Context(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) signIns(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	out, err := h.queries.ListSignIn(c.Context(), env, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
