package hostedhttp

import (
	"slices"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/gofiber/fiber/v2"
)

// Consenter records a consent decision on an authorization waiting for it
// and answers like /oauth/authorize/complete (oauthhttp.Handler.Consent).
type Consenter func(c *fiber.Ctx, ticket string, decision oauth.ConsentDecision) error

// Consents enables the consent page (/hosted/consent); a custom UI's
// decision is oauthhttp.Handler.ConsentDecision.
func (h *Handler) Consents(consent Consenter) { h.consent = consent }

func (h *Handler) consentPages(pages map[string]fiber.Handler) {
	if h.consent == nil {
		return
	}
	pages["GET /hosted/consent"] = h.consentPage
	pages["POST /hosted/consent"] = h.decide
}

// ConsentView is what the consent page shows: the client as the refusal
// page shows it (host first, a name only when a preset vouches for it),
// the server, and the scopes asked, apart from those the user does not
// hold yet.
type ConsentView struct {
	Application ClientApplication
	Resource    string
	Scopes      []ScopeLine
	Unheld      []ScopeLine
	Agreed      []ScopeLine
}

// ScopeLine is a scope as the page lists it: its words, and its name when
// the words are not the name itself.
type ScopeLine struct {
	Name  string
	Label string
	// Detail is the permission's description, when it has one (D40).
	Detail string
}

// consentScopes labels scopes: profile data scopes in the page's
// language, permissions with their description's display name and sentence
// (words, in the page's language) or else by name.
func consentScopes(v view, scopes []string, words map[string]oauth.ScopeText) []ScopeLine {
	out := make([]ScopeLine, 0, len(scopes))
	for _, s := range scopes {
		line := ScopeLine{Name: s, Label: s}
		if slices.Contains(oauth.ConsentableOIDCScopes, s) {
			line.Label = v.T("hosted.consent.scope." + s)
		} else if t, ok := words[s]; ok {
			if t.DisplayName != "" {
				line.Label = t.DisplayName
			}
			line.Detail = t.Description
		}
		out = append(out, line)
	}
	return out
}

// consentView renders the page of an authorization waiting for consent.
func (h *Handler) consentView(c *fiber.Ctx, r hosted.Request) (view, error) {
	page, err := h.flow.ConsentPage(c.UserContext(), r, c.Get(fiber.HeaderAcceptLanguage))
	if err != nil {
		return view{}, err
	}
	prompt := page.Prompt
	v := view{Lang: page.Settings.Negotiate(page.Language, c.Get(fiber.HeaderAcceptLanguage)), Brand: brandOf(page.Settings, ""), Ticket: r.Ticket, Account: page.Account}
	h.word(c, &v, prompt.Environment, page.Texts)
	app := ClientApplication{Host: prompt.Client.Host, Verified: prompt.Client.Verified, Name: prompt.Client.Name, Logo: prompt.Client.LogoURI}
	resource := prompt.ResourceName
	if resource == "" {
		resource = prompt.Resource
	}
	v.Consent = &ConsentView{Application: app, Resource: resource, Scopes: consentScopes(v, prompt.Pending, page.Words), Unheld: consentScopes(v, prompt.Unheld, page.Words), Agreed: consentScopes(v, prompt.Agreed, page.Words)}
	who := app.Verified
	if who == "" {
		who = app.Host
	}
	if who == "" {
		who = v.T("hosted.consent.this_application")
	}
	v.Title = v.T("hosted.consent.title")
	v.Subtitle = v.V("hosted.consent.subtitle", i18n.Vars{"application": who, "resource": resource})
	if len(prompt.Agreed) > 0 {
		v.Subtitle = v.V("hosted.consent.subtitle_more", i18n.Vars{"application": who, "resource": resource})
	}
	return v, nil
}

// consentPage asks the user to allow or deny what the authorization asks
// for. A ticket that is not waiting (decided, expired, another browser)
// gets the expired page.
func (h *Handler) consentPage(c *fiber.Ctx) error {
	r := h.request(c)
	v, err := h.consentView(c, r)
	if err != nil {
		return h.consentFailed(c, err)
	}
	return render(c, fiber.StatusOK, "consent", v)
}

// decide records the decision of the consent page: allow sends the
// browser to the client with a code, deny with access_denied.
func (h *Handler) decide(c *fiber.Ctx) error {
	r := h.request(c)
	err := h.consent(c, r.Ticket, oauth.ConsentDecision{Approve: c.FormValue("decision") == "allow", UI: oauth.ConsentUIHosted})
	if err != nil {
		return h.consentFailed(c, err)
	}
	return nil
}

// consentFailed ends the consent page with a message: a dead ticket or
// binding reads as an expired sign-in, like the sign-in pages.
func (h *Handler) consentFailed(c *fiber.Ctx, err error) error {
	if oauth.IsClientRefusal(err) {
		return h.Refusal(c, err)
	}
	lang := language(c, "")
	status, text := failed(c, view{Lang: lang}, err)
	var e *errx.Error
	if status == fiber.StatusUnauthorized || (errx.As(err, &e) && e.Code == oauth.CodeConsentNotPending) {
		text = i18n.T(lang, "hosted.expired")
	}
	return message(c, lang, status, i18n.T(lang, "hosted.title.expired"), text)
}
