package hosted

import (
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Authorization describes a pending OAuth authorization to a custom
// sign-in UI (GET /identity/v1/authorize/:ticket): what hosted pages would
// render for it. Branding follows the same layering as the hosted pages;
// Methods are the client's options within the environment's sign-in
// policy (organizations narrow further when chosen).
type Authorization struct {
	Client      identity.ClientID      `json:"client_id"`
	Environment identity.EnvironmentID `json:"environment_id"`
	Application identity.ApplicationID `json:"application_id"`
	Resource    identity.ResourceID    `json:"resource_id"`
	Audience    string                 `json:"audience"`
	Scopes      []string               `json:"scopes"`
	// Organization is the authorize request's organization hint
	// (organization_id or the urn:iamkit:org:id: scope): the sign-in must
	// complete in it.
	Organization *identity.OrganizationID `json:"organization_id,omitempty"`
	// LoginHint is the request's login_hint, to prefill the identifier.
	LoginHint string `json:"login_hint,omitempty"`
	// Locale is the language to show: the request's ui_locales, the
	// branding's language, else the browser's, within Languages.
	Locale string `json:"locale"`
	// Languages are the enabled languages (every available one when the
	// environment lists none).
	Languages []string `json:"languages"`
	Branding  Branding `json:"branding"`
	Methods   Methods  `json:"methods"`
	// Connections are the environment connections offered as buttons.
	Connections []federation.ConnectionSummary `json:"connections"`
	// Texts are the custom sign-in texts for Locale (hosted.* keys; the
	// catalog's words otherwise).
	Texts i18n.Texts `json:"texts"`
}

// Branding is the look of a sign-in for a custom UI.
type Branding struct {
	DisplayName string `json:"display_name"`
	LogoURL     string `json:"logo_url"`
	AccentColor string `json:"accent_color"`
	Theme       Theme  `json:"theme"`
	Legal       Legal  `json:"legal"`
}

// Methods are the sign-in methods offered.
type Methods struct {
	Password        bool `json:"password"`
	EmailCode       bool `json:"email_code"`
	OrganizationSSO bool `json:"organization_sso"`
	Passkey         bool `json:"passkey"`
	Signup          bool `json:"signup"`
	PasswordReset   bool `json:"password_reset"`
	// Terms asks sign-up to accept the terms (Branding.Legal.TermsURL).
	Terms bool `json:"terms"`
}

// MethodsOf are the methods options offer.
func MethodsOf(options SignIn) Methods {
	return Methods{Password: options.Password, EmailCode: options.EmailCode, OrganizationSSO: options.OrganizationSSO,
		Passkey: options.Passkey, Signup: options.Signup, PasswordReset: options.PasswordReset, Terms: options.Terms}
}

// BrandingOf is the custom-UI view of settings.
func BrandingOf(settings Settings) Branding {
	out := Branding{DisplayName: settings.DisplayName, LogoURL: settings.LogoURL, AccentColor: settings.AccentColor, Theme: settings.Theme}
	if settings.Legal != nil {
		out.Legal = *settings.Legal
	}
	return out
}
