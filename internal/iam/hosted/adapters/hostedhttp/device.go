package hostedhttp

import (
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Devices enables /hosted/device, where a user approves a device
// authorization by typing its user code.
func (h *Handler) Devices(devices hosted.Devices) { h.devices = devices }

// DevicePages are the device approval pages (none without Devices).
func (h *Handler) devicePages(pages map[string]fiber.Handler) {
	if h.devices == nil {
		return
	}
	pages["GET /hosted/device"] = h.devicePage
	pages["POST /hosted/device"] = h.deviceLookup
	pages["POST /hosted/device/approve"] = h.deviceApprove
	pages["POST /hosted/device/deny"] = h.deviceDeny
}

// deviceView brands a device page with the environment (and the client's
// own style) when known.
func (h *Handler) deviceView(c *fiber.Ctx, request *oauth.DeviceRequest) view {
	settings := hosted.Settings{}
	if request != nil {
		if s, err := h.queries.ClientSettings(c.UserContext(), request.Environment, request.Client); err == nil {
			settings = s
		} else if s, err := h.queries.Settings(c.UserContext(), request.Environment); err == nil {
			settings = s
		}
	}
	v := view{Lang: environmentLanguage(c, settings), Brand: brandOf(settings, "")}
	if request != nil {
		h.word(c, &v, request.Environment, hosted.TextScope{Client: request.Client})
	}
	v.Title = v.T("hosted.device.title")
	return v
}

// devicePage asks for the code shown on the device (prefilled from
// verification_uri_complete; the user still confirms).
func (h *Handler) devicePage(c *fiber.Ctx) error {
	v := h.deviceView(c, nil)
	v.Subtitle, v.UserCode = v.T("hosted.device.enter"), c.Query("user_code")
	return render(c, fiber.StatusOK, "device", v)
}

// deviceLookup shows which application asks for access before the user
// signs in.
func (h *Handler) deviceLookup(c *fiber.Ctx) error {
	code := c.FormValue("user_code")
	request, err := h.devices.DeviceRequest(c.UserContext(), code)
	if err != nil {
		return h.deviceRetry(c, code, err)
	}
	v := h.deviceView(c, &request)
	v.UserCode, v.Device = oauth.FormatUserCode(oauth.NormalizeUserCode(code)), &request
	v.Subtitle = v.T("hosted.device.confirm", request.Application)
	return render(c, fiber.StatusOK, "device-confirm", v)
}

// deviceRetry shows the code page again with why the code was refused.
func (h *Handler) deviceRetry(c *fiber.Ctx, code string, err error) error {
	v := h.deviceView(c, nil)
	v.Subtitle, v.UserCode = v.T("hosted.device.enter"), code
	var e *errx.Error
	if errx.As(err, &e) && e.Type == errx.TypeNotFound {
		v.Error = v.T("hosted.device.invalid")
		return render(c, fiber.StatusNotFound, "device", v)
	}
	status, text := failed(c, v, err)
	v.Error = text
	return render(c, status, "device", v)
}

// deviceApprove starts the hosted sign-in for the device: the finished
// login approves it instead of redirecting to an application.
func (h *Handler) deviceApprove(c *fiber.Ctx) error {
	code := c.FormValue("user_code")
	ticket, binding, err := h.devices.StartDevice(c.UserContext(), code)
	if err != nil {
		return h.deviceRetry(c, code, err)
	}
	c.Cookie(&fiber.Cookie{Name: authorizationCookie, Value: binding, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: int(config.OAuthAuthorizationTicketTTL.Seconds())})
	c.Set("Cache-Control", "no-store")
	return c.Redirect("/hosted/login?"+url.Values{"ticket": {ticket}}.Encode(), fiber.StatusSeeOther)
}

func (h *Handler) deviceDeny(c *fiber.Ctx) error {
	code := c.FormValue("user_code")
	request, err := h.devices.DeviceRequest(c.UserContext(), code)
	if err == nil {
		err = h.devices.DenyDevice(c.UserContext(), code)
	}
	if err != nil {
		return h.deviceRetry(c, code, err)
	}
	v := h.deviceView(c, &request)
	v.Title, v.Notice = v.T("hosted.device.denied_title"), v.T("hosted.device.denied")
	return render(c, fiber.StatusOK, "message", v)
}

// DeviceApproved is the page a finished device approval shows (wired to
// oauthhttp.Handler.Devices in bootstrap).
func (h *Handler) DeviceApproved(c *fiber.Ctx, environment identity.EnvironmentID) error {
	settings, err := h.queries.Settings(c.UserContext(), environment)
	if err != nil {
		settings = hosted.Settings{}
	}
	v := view{Lang: environmentLanguage(c, settings), Brand: brandOf(settings, "")}
	h.word(c, &v, environment, hosted.TextScope{})
	v.Title, v.Notice = v.T("hosted.device.approved_title"), v.T("hosted.device.approved")
	return render(c, fiber.StatusOK, "message", v)
}

// PostForm renders the page that posts a SAML response to a service
// provider: a nonce-bound script submits it at once, the visible button
// does it without JavaScript.
func (h *Handler) PostForm(c *fiber.Ctx, environment identity.EnvironmentID, action string, fields [][2]string) error {
	settings, err := h.queries.Settings(c.UserContext(), environment)
	if err != nil {
		settings = hosted.Settings{}
	}
	v := view{Lang: environmentLanguage(c, settings), Brand: brandOf(settings, ""), Post: &PostForm{Action: action, Fields: fields}}
	h.word(c, &v, environment, hosted.TextScope{})
	v.Title, v.Subtitle = v.T("hosted.title.redirecting"), v.T("hosted.subtitle.redirecting")
	return render(c, fiber.StatusOK, "post", v)
}
