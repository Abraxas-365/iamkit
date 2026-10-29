package hostedhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// ClientApplication is what the page of a refused application shows (M5).
// Only the host of the client_id is vouched for: a preset-verified client
// shows the preset's name with a check; any other name is the document's
// own claim and is marked unverified. The logo is shown only when it is
// served from the client_id's own host (oauth.LogoShown); IAMKit proxies
// no image. A dynamically registered client has no host (Host ""): only
// its unverified name is shown.
type ClientApplication struct {
	Host string
	// Verified is the preset's name ("" when the client matches none).
	Verified string
	// Name is the document's client_name (shown unverified).
	Name string
	Logo string
}

// Refusal is the page for an external client the server cannot serve yet:
// waiting for IT, blocked, too many waiting, registered clients only, or
// documents disabled. It is a page, never a redirect: nothing is trusted
// about the client's redirect URIs before IT approves it.
func (h *Handler) Refusal(c *fiber.Ctx, err error) error {
	var e *errx.Error
	_ = errx.As(err, &e)
	var environment identity.EnvironmentID
	app := ClientApplication{}
	if e != nil {
		if raw, ok := e.Details["environment_id"].(string); ok {
			environment, _ = identity.ParseEnvironmentID(raw)
		}
		id, _ := e.Details["client_id"].(string)
		name, _ := e.Details["client_name"].(string)
		logo, _ := e.Details["logo_uri"].(string)
		app = ClientApplication{Host: oauth.ClientHost(id), Name: name, Logo: oauth.LogoShown(id, logo)}
		if p, ok := oauth.PresetForClient(id); ok {
			app.Verified = p.Name
		}
	}
	settings := hosted.Settings{}
	if !environment.IsZero() {
		if s, err := h.queries.Settings(c.UserContext(), environment); err == nil {
			settings = s
		}
	}
	v := view{Lang: environmentLanguage(c, settings), Brand: brandOf(settings, ""), Application: &app}
	h.word(c, &v, environment, hosted.TextScope{})
	status := fiber.StatusForbidden
	code := ""
	if e != nil {
		code = e.Code
		status = e.HTTPStatus
	}
	switch code {
	case oauth.CodeClientPending:
		v.Title, v.Notice = v.T("hosted.client.title.pending"), v.T("hosted.client.pending")
	case oauth.CodeClientBlocked:
		v.Title, v.Error = v.T("hosted.client.title.blocked"), v.T("hosted.client.blocked")
	case oauth.CodeClientBacklog:
		v.Title, v.Error = v.T("hosted.client.title.unavailable"), v.T("hosted.client.backlog")
	case oauth.CodeClientRequestLimit:
		v.Title, v.Error = v.T("hosted.client.title.unavailable"), v.T("hosted.client.request_limit")
	case oauth.CodeClientRegisteredOnly:
		v.Title, v.Error = v.T("hosted.client.title.unavailable"), v.T("hosted.client.registered_only")
		v.NextStep = v.T("hosted.client.next_step")
	default:
		v.Title, v.Error = v.T("hosted.client.title.unavailable"), v.T("hosted.client.disabled")
		v.NextStep = v.T("hosted.client.next_step")
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return render(c, status, "client", v)
}

// Label is the application's name line: verified (preset) or unverified.
func (a ClientApplication) Label(v view) string {
	switch {
	case a.Verified != "":
		return v.V("hosted.client.verified", i18n.Vars{"name": a.Verified})
	case a.Name != "":
		return v.V("hosted.client.unverified", i18n.Vars{"name": a.Name})
	}
	return ""
}
