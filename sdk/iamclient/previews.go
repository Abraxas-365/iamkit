package iamclient

import (
	"context"
	"encoding/json"
	"net/url"
)

// ── Previews ──

// PagePreview is a hosted page rendered as an HTML document (meant for a
// sandboxed iframe).
type PagePreview struct {
	HTML string `json:"html"`
}

// PreviewMethods are the sign-in methods a preview shows.
type PreviewMethods struct {
	Password        bool            `json:"password"`
	EmailCode       bool            `json:"email_code"`
	OrganizationSSO bool            `json:"organization_sso"`
	Connections     []PreviewButton `json:"connections"`
}

// PreviewButton is a "Continue with" button of a preview.
type PreviewButton struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

// PageOptions choose the page to preview: Page (identify, password, code,
// reset, organization, mfa, enroll, recovery, invite, message; default
// identify), Scheme ("light" or "dark"), Locale (default the environment
// language) and the sign-in methods shown.
type PageOptions struct {
	Page   string          `json:"page,omitempty"`
	Scheme string          `json:"scheme,omitempty"`
	Locale string          `json:"locale,omitempty"`
	SignIn *PreviewMethods `json:"sign_in,omitempty"`
}

// PreviewPage renders a hosted page with the saved branding and texts of
// scope (zero: the environment default).
func (e Environment) PreviewPage(ctx context.Context, scope TextScope, options PageOptions) (PagePreview, error) {
	query := url.Values{}
	for key, value := range map[string]string{"page": options.Page, "scheme": options.Scheme, "locale": options.Locale, "client": scope.ClientID, "organization": scope.OrganizationID} {
		if value != "" {
			query.Set(key, value)
		}
	}
	if options.SignIn != nil {
		raw, err := json.Marshal(options.SignIn)
		if err != nil {
			return PagePreview{}, err
		}
		query.Set("sign_in", string(raw))
	}
	var out PagePreview
	err := e.client.do(ctx, "GET", e.path("login-settings/preview"), query, nil, &out)
	return out, err
}

// DraftPreview is unsaved branding to preview: Settings (an environment
// default or client style), or Organization overrides laid over the saved
// environment default. ClientID picks whose sign-in options are shown.
type DraftPreview struct {
	PageOptions
	Settings     *LoginSettings        `json:"settings,omitempty"`
	Organization *OrganizationBranding `json:"organization,omitempty"`
	ClientID     string                `json:"client_id,omitempty"`
}

// PreviewDraftPage renders a hosted page with unsaved branding.
func (e Environment) PreviewDraftPage(ctx context.Context, input DraftPreview) (PagePreview, error) {
	var out PagePreview
	err := e.operation(ctx, "POST", []string{"login-settings", "preview"}, input, &out)
	return out, err
}

// PreviewSignInTexts renders a hosted page with the saved branding of
// scope and unsaved custom texts in options.Locale.
func (e Environment) PreviewSignInTexts(ctx context.Context, scope TextScope, options PageOptions, texts map[string]string) (PagePreview, error) {
	input := struct {
		PageOptions
		Texts          map[string]string `json:"texts"`
		ClientID       string            `json:"client_id,omitempty"`
		OrganizationID string            `json:"organization_id,omitempty"`
	}{options, texts, scope.ClientID, scope.OrganizationID}
	if input.Texts == nil {
		input.Texts = map[string]string{}
	}
	var out PagePreview
	err := e.operation(ctx, "POST", []string{"login-settings", "texts", "preview"}, input, &out)
	return out, err
}
