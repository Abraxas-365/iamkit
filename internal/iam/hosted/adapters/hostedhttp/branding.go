package hostedhttp

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
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
	out, err := h.queries.ListClientSettings(c.UserContext(), env, httpx.PaginationFromCtx(c))
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
	out, err := h.queries.ClientSettings(c.UserContext(), env, id)
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
	out, err := h.commands.SaveClientSettings(c.UserContext(), h.mutation(c), id, input)
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
	if err = h.commands.DeleteClientSettings(c.UserContext(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Preview is a hosted page rendered with sample data, for the console to
// show in a sandboxed frame.
type Preview struct {
	HTML string `json:"html"`
}

// Methods is which sign-in methods a preview shows: the email steps and
// the "Continue with" buttons. Without it the preview shows every method
// with sample Google and Microsoft buttons. Only the sign-in and password
// pages depend on it.
type Methods struct {
	Password        bool     `json:"password"`
	EmailCode       bool     `json:"email_code"`
	OrganizationSSO bool     `json:"organization_sso"`
	Connections     []Button `json:"connections"`
}

// Button is a "Continue with" button of a preview.
type Button struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

const maxButtonName = 100

var previewProviders = []string{federation.ProviderGoogle, federation.ProviderMicrosoft, federation.ProviderGitHub, federation.ProviderApple, federation.ProviderOIDC}

// apply shows the methods on a sample page.
func (m Methods) apply(v *view) error {
	if len(m.Connections) > hosted.MaxSignInConnections {
		return errx.Validation("sign_in.connections has at most 50 buttons")
	}
	buttons := make([]federation.ConnectionSummary, 0, len(m.Connections))
	for _, b := range m.Connections {
		name := strings.TrimSpace(b.Name)
		if name == "" || utf8.RuneCountInString(name) > maxButtonName {
			return errx.Validation("sign_in.connections name is required (up to 100 characters)")
		}
		if !slices.Contains(previewProviders, b.Provider) {
			return errx.Validation("sign_in.connections provider must be one of " + strings.Join(previewProviders, ", "))
		}
		buttons = append(buttons, federation.ConnectionSummary{Name: name, Provider: b.Provider})
	}
	signIn := hosted.SignIn{Password: m.Password, EmailCode: m.EmailCode, OrganizationSSO: m.OrganizationSSO, PasswordReset: m.Password}
	if !signIn.EmailForm() && len(buttons) == 0 {
		return errx.Validation("sign_in must show at least one method")
	}
	v.SignIn = signIn
	if v.Connections != nil {
		v.Connections = buttons
	}
	return nil
}

// savedPreview renders a page with the saved style of ?client= (or the
// environment default), with ?organization='s overrides. ?sign_in= is
// optional Methods as JSON; ?locale= the page language.
func (h *Handler) savedPreview(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	var scope hosted.TextScope
	if raw := c.Query("client"); raw != "" {
		id, err := identity.ParseClientID(raw)
		if err != nil {
			return errx.Validation("invalid client id")
		}
		scope.Client = id
	}
	if raw := c.Query("organization"); raw != "" {
		org, err := identity.ParseOrganizationID(raw)
		if err != nil {
			return errx.Validation("invalid organization id")
		}
		scope.Organization = org
	}
	var methods *Methods
	if raw := c.Query("sign_in"); raw != "" {
		methods = &Methods{}
		if err := json.Unmarshal([]byte(raw), methods); err != nil {
			return errx.Validation("sign_in must be a JSON object")
		}
	}
	settings, locale, err := h.savedBranding(c, env, scope)
	if err != nil {
		return err
	}
	return h.preview(c, settings, previewInput{Page: c.Query("page"), Scheme: c.Query("scheme"), Locale: c.Query("locale"), Fallback: locale, SignIn: methods, TextScope: scope})
}

// textsPreview renders a page in the saved branding of the body's client
// or organization with unsaved custom texts (the sign-in texts editor).
func (h *Handler) textsPreview(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	var input struct {
		previewInput
		Client       *identity.ClientID       `json:"client_id"`
		Organization *identity.OrganizationID `json:"organization_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if input.Client != nil {
		input.TextScope.Client = *input.Client
	}
	if input.Organization != nil {
		input.TextScope.Organization = *input.Organization
	}
	if input.Texts == nil {
		input.Texts = map[string]string{}
	}
	settings, locale, err := h.savedBranding(c, env, input.TextScope)
	if err != nil {
		return err
	}
	input.Fallback = locale
	return h.preview(c, settings, input.previewInput)
}

// savedBranding is the saved branding of a scope (the client's style, or
// the environment default, with the organization's overrides) and the
// environment language.
func (h *Handler) savedBranding(c *fiber.Ctx, env identity.EnvironmentID, scope hosted.TextScope) (hosted.Settings, string, error) {
	base, err := h.queries.Settings(c.UserContext(), env)
	if err != nil {
		return hosted.Settings{}, "", err
	}
	locale := ""
	if base.Locale != nil {
		locale = *base.Locale
	}
	if scope.Client.IsZero() && scope.Organization.IsZero() {
		return base, locale, nil
	}
	settings, err := h.queries.Branded(c.UserContext(), env, scope.Client, scope.Organization)
	return settings, locale, err
}

// draftPreview renders a page with an unsaved style, or with unsaved
// organization overrides laid over the environment default.
func (h *Handler) draftPreview(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	var input struct {
		previewInput
		Settings     hosted.Settings              `json:"settings"`
		Organization *hosted.OrganizationSettings `json:"organization"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if input.Organization != nil {
		settings, err := h.queries.DraftOrganization(c.UserContext(), env, *input.Organization)
		if err != nil {
			return err
		}
		if settings.Locale != nil {
			input.Fallback = *settings.Locale
		}
		return h.preview(c, settings, input.previewInput)
	}
	settings, err := h.queries.Draft(c.UserContext(), env, input.Settings)
	if err != nil {
		return err
	}
	if settings.Locale != nil {
		input.Fallback = *settings.Locale
	} else if saved, err := h.queries.Settings(c.UserContext(), env); err == nil && saved.Locale != nil {
		// A client style has no language: it is the environment's.
		input.Fallback = *saved.Locale
	}
	return h.preview(c, settings, input.previewInput)
}

// previewInput is what to preview: the page, its color scheme, its
// language (Locale, else Fallback, the environment language, else
// English) and, for the sign-in pages, the methods.
type previewInput struct {
	Page     string   `json:"page"`
	Scheme   string   `json:"scheme"`
	Locale   string   `json:"locale"`
	Fallback string   `json:"-"`
	SignIn   *Methods `json:"sign_in"`
	// Texts are unsaved custom texts in the preview language, for
	// TextScope (nil: the saved ones).
	Texts     map[string]string `json:"texts"`
	TextScope hosted.TextScope  `json:"-"`
}

func (h *Handler) preview(c *fiber.Ctx, settings hosted.Settings, in previewInput) error {
	page := in.Page
	if page == "" {
		page = "identify"
	}
	if in.Locale != "" && !i18n.Supported(in.Locale) {
		return errx.Validation("locale must be an available language")
	}
	lang := in.Locale
	if lang == "" {
		lang = i18n.Resolve(in.Fallback)
	}
	environment, _ := identity.ParseEnvironmentID(c.Params("environment"))
	texts, err := h.previewTexts(c, environment, lang, in)
	if err != nil {
		return err
	}
	v, ok := sample(page, lang, texts)
	if !ok {
		return errx.Validation("page must be one of identify, password, code, reset, organization, mfa, enroll, recovery, invite, message")
	}
	if in.Scheme != "" && in.Scheme != hosted.ModeLight && in.Scheme != hosted.ModeDark {
		return errx.Validation("scheme must be light or dark")
	}
	if in.SignIn != nil && (page == "identify" || page == "password") {
		if err := in.SignIn.apply(&v); err != nil {
			return err
		}
	}
	v.Brand = brandOf(settings, in.Scheme)
	if page == "signup" {
		// The checkbox shows when sign-up requires accepting the terms
		// (the sign-in policy): preview it once there are terms to link.
		v.SignIn.Terms = v.Brand.Legal.TermsURL != ""
	}
	out, err := document(page, &v)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(Preview{HTML: string(out)})
}

// previewTexts are the custom texts a preview in lang shows: the draft
// laid over the saved environment texts, else the scope's saved wording.
func (h *Handler) previewTexts(c *fiber.Ctx, environment identity.EnvironmentID, lang string, in previewInput) (i18n.Texts, error) {
	if h.texts.queries == nil || environment.IsZero() {
		return nil, nil
	}
	if in.Texts != nil {
		draft := hosted.Texts{Locale: lang, Messages: in.Texts}
		if !in.TextScope.Client.IsZero() {
			draft.Client = &in.TextScope.Client
		}
		if !in.TextScope.Organization.IsZero() {
			draft.Organization = &in.TextScope.Organization
		}
		return h.texts.queries.DraftWording(c.UserContext(), environment, draft)
	}
	return h.texts.queries.Wording(c.UserContext(), environment, in.TextScope, lang)
}

// sample is example data for each previewable page, in lang with the
// custom texts.
func sample(page, lang string, texts i18n.Texts) (view, bool) {
	const email = "jane@example.com"
	connection := identity.ConnectionID{}
	all := hosted.DefaultSignIn(identity.EnvironmentID{}, identity.ClientID{}).Within(authentication.DefaultSignInPolicy())
	v := view{Lang: lang, Texts: texts}
	t := v.T
	switch page {
	case "identify":
		v.Title, v.SignIn = t("hosted.title.sign_in"), all
		v.Connections = []federation.ConnectionSummary{{ID: connection, Name: "Google", Provider: federation.ProviderGoogle}, {ID: connection, Name: "Microsoft", Provider: federation.ProviderMicrosoft}}
	case "password":
		v.Title, v.Email, v.SignIn = t("hosted.title.sign_in"), email, all
	case "code":
		v.Title, v.Email, v.Notice = t("hosted.title.check_email"), email, t("hosted.notice.code_sent", email)
	case "reset":
		v.Title, v.Email, v.Notice = t("hosted.title.reset"), email, t("hosted.notice.reset_sent", email)
	case "organization":
		v.Title, v.Subtitle = t("hosted.title.organization"), t("hosted.subtitle.organization")
		v.Organizations = []authentication.Organization{{Name: "Acme Inc."}, {Name: "Globex"}}
	case "mfa":
		v.Title, v.Subtitle, v.Error = t("hosted.title.mfa"), t("hosted.subtitle.mfa"), t("hosted.error.mfa_code")
	case "enroll":
		v.Title, v.Subtitle, v.Secret = t("hosted.title.enroll"), t("hosted.subtitle.enroll"), "JBSWY3DPEHPK3PXP"
		if code, err := qr.Encode("otpauth://totp/Example:jane@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example", qr.M); err == nil {
			code.Scale = 4
			v.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()))
		}
	case "recovery":
		v.Title, v.Subtitle = t("hosted.title.recovery"), t("hosted.subtitle.recovery")
		v.RecoveryCodes = []string{"k7d2-9xqa", "m3p8-2rtn", "c5w1-7hve", "q9z4-6bly", "t2f6-4ngs", "x8j3-1kdm"}
	case "invite":
		v.Title, v.Subtitle = t("hosted.invitation.join", "Acme Inc."), t("hosted.invitation.invited", "Acme Inc.")
		v.Invite = &invitation.Preview{Email: "j***@example.com", OrganizationName: "Acme Inc.", PasswordRequired: true}
	case "message":
		v.Title, v.Notice = t("hosted.invitation.accepted"), t("hosted.invitation.joined", "Acme Inc.")
	case "signup":
		v.Title, v.SignIn = t("hosted.title.signup"), all
	case "signup-code":
		v.Title, v.Email, v.Notice = t("hosted.title.check_email"), email, t("hosted.notice.signup_sent", email)
	default:
		return view{}, false
	}
	return v, true
}

func (h *Handler) signIn(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	id, err := client(c)
	if err != nil {
		return err
	}
	out, err := h.queries.SignIn(c.UserContext(), env, id)
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
	// Clients saved before sign-up existed omit it: they keep offering it.
	input := hosted.SignIn{Signup: true}
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SaveSignIn(c.UserContext(), h.mutation(c), id, input)
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
	if err = h.commands.DeleteSignIn(c.UserContext(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) signIns(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	out, err := h.queries.ListSignIn(c.UserContext(), env, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func organization(c *fiber.Ctx) (identity.OrganizationID, error) {
	id, err := identity.ParseOrganizationID(c.Params("organization"))
	if err != nil {
		return id, errx.Validation("invalid organization id")
	}
	return id, nil
}

// organizationStyle is the organization's branding overrides (every field
// null when it has none).
func (h *Handler) organizationStyle(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	id, err := organization(c)
	if err != nil {
		return err
	}
	out, err := h.queries.OrganizationSettings(c.UserContext(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) saveOrganizationStyle(c *fiber.Ctx) error {
	id, err := organization(c)
	if err != nil {
		return err
	}
	var input hosted.OrganizationSettings
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SaveOrganizationSettings(c.UserContext(), h.mutation(c), id, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteOrganizationStyle(c *fiber.Ctx) error {
	id, err := organization(c)
	if err != nil {
		return err
	}
	if err = h.commands.DeleteOrganizationSettings(c.UserContext(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
