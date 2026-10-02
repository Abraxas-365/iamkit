package iamclient

import (
	"context"
	"net/url"
)

// SignInTexts are custom wordings of the hosted pages in one language, for
// the environment, one OAuth client (ClientID) or one organization
// (OrganizationID). Pages resolve each text organization › client ›
// environment › IAMKit's own wording. Texts maps catalog keys
// ("hosted.form.continue") to plain-text messages that keep the catalog
// message's placeholders (%s, {count}).
type SignInTexts struct {
	EnvironmentID  string            `json:"environment_id,omitempty"`
	ClientID       string            `json:"client_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	Locale         string            `json:"locale"`
	Texts          map[string]string `json:"texts"`
	UpdatedAt      string            `json:"updated_at,omitempty"`
}

// TextScope names whose texts: zero is the environment's; set at most one
// of ClientID and OrganizationID.
type TextScope struct {
	ClientID       string
	OrganizationID string
}

func (s TextScope) parts(locale string) []string {
	parts := []string{"login-settings"}
	switch {
	case s.OrganizationID != "":
		parts = append(parts, "organizations", s.OrganizationID)
	case s.ClientID != "":
		parts = append(parts, "clients", s.ClientID)
	}
	return append(parts, "texts", locale)
}

// SignInText is one customizable text of a language: IAMKit's wording,
// the placeholders a custom message must keep, and its longest length.
type SignInText struct {
	Key          string   `json:"key"`
	Default      string   `json:"default"`
	Placeholders []string `json:"placeholders"`
	MaxLength    int      `json:"max_length"`
}

// SignInTextCatalog lists the customizable texts of locale.
func (e Environment) SignInTextCatalog(ctx context.Context, locale string) ([]SignInText, error) {
	var out struct {
		Items []SignInText `json:"items"`
	}
	err := e.client.do(ctx, "GET", e.path("login-settings/texts/catalog"), url.Values{"locale": {locale}}, nil, &out)
	return out.Items, err
}

// SignInTextSets lists the scopes and languages with custom texts.
func (e Environment) SignInTextSets(ctx context.Context) ([]SignInTexts, error) {
	return list[SignInTexts](e, ctx, "login-settings/texts")
}

// SignInTexts returns a scope's custom texts in locale (Texts empty when
// it has none).
func (e Environment) SignInTexts(ctx context.Context, scope TextScope, locale string) (SignInTexts, error) {
	var out SignInTexts
	err := e.operation(ctx, "GET", scope.parts(locale), nil, &out)
	return out, err
}

// SetSignInTexts replaces a scope's custom texts in locale; keys left out
// (or empty) inherit.
func (e Environment) SetSignInTexts(ctx context.Context, scope TextScope, locale string, texts map[string]string) (SignInTexts, error) {
	var out SignInTexts
	err := e.operation(ctx, "PUT", scope.parts(locale), map[string]any{"texts": texts}, &out)
	return out, err
}

// DeleteSignInTexts returns a scope's language to the inherited texts.
func (e Environment) DeleteSignInTexts(ctx context.Context, scope TextScope, locale string) error {
	return e.operation(ctx, "DELETE", scope.parts(locale), nil, nil)
}
