package oauthhttp

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/ory/fosite"
)

// Actions runs the environment's token hooks.
func (h *Handler) Actions(actions oauth.Actions) { h.actions = actions }

// tokenInput is the input of a token hook.
func tokenInput(client *oauth.Client, user identity.UserID, organization identity.OrganizationID, amr, scopes []string) action.Input {
	in := action.Input{Application: &client.Application, Client: client.ID.String(), User: &action.UserInput{ID: &user}, Method: amr, Scopes: scopes}
	if !organization.IsZero() {
		in.Organization = &organization
	}
	return in
}

// tokenHooks runs pre_access_token and, with openid, pre_id_token on a
// fresh session: their claims go into the access and ID tokens. A denial
// or interrupting failure is returned.
func (h *Handler) tokenHooks(ctx context.Context, client *oauth.Client, session *oauthfosite.Session, user identity.UserID, organization identity.OrganizationID, amr, scopes []string) error {
	if h.actions == nil {
		return nil
	}
	build := func() action.Input { return tokenInput(client, user, organization, amr, scopes) }
	if err := h.accessHook(ctx, client, session, build); err != nil {
		return err
	}
	if !slices.Contains(scopes, "openid") {
		return nil
	}
	result, err := h.actions.Run(ctx, client.Environment, action.PreIDToken, build)
	if err != nil {
		return err
	}
	for name, value := range result.ClaimValues() {
		if !reserved(name, session.IDTokenClaims().Extra) {
			session.IDTokenClaims().Extra[name] = value
		}
	}
	return nil
}

// accessHook runs pre_access_token, replacing the claims an earlier run
// added (refresh) with the new answer.
func (h *Handler) accessHook(ctx context.Context, client *oauth.Client, session *oauthfosite.Session, build func() action.Input) error {
	for _, name := range session.Injected {
		delete(session.AccessClaims.Extra, name)
	}
	session.Injected = nil
	if h.actions == nil {
		return nil
	}
	result, err := h.actions.Run(ctx, client.Environment, action.PreAccessToken, build)
	if err != nil {
		return err
	}
	for name, value := range result.ClaimValues() {
		if reserved(name, session.AccessClaims.Extra) {
			continue
		}
		session.AccessClaims.Extra[name] = value
		session.Injected = append(session.Injected, name)
	}
	slices.Sort(session.Injected)
	return nil
}

// reserved: a claim IAMKit sets itself (checked again here, so a claim
// IAMKit adds later is never overwritten).
func reserved(name string, current map[string]any) bool {
	if slices.Contains(action.ReservedClaims, name) {
		return true
	}
	_, taken := current[name]
	return taken
}

// userInfoClaims are the standard members UserInfo answers itself.
var userInfoClaims = []string{"sub", "environment_id", "organization_id", "name", "email", "email_verified"}

// userInfoHook runs pre_userinfo for an OAuth access token.
func (h *Handler) userInfoHook(ctx context.Context, token authentication.Token) (map[string]json.RawMessage, error) {
	if h.actions == nil {
		return nil, nil
	}
	result, err := h.actions.Run(ctx, token.EnvironmentID, action.PreUserInfo, func() action.Input {
		subject := token.Subject
		in := action.Input{Client: token.OAuthClientID.String(), User: &action.UserInput{ID: &subject}, Method: token.AMR, Scopes: token.Scopes}
		if !token.OrganizationID.IsZero() {
			organization := token.OrganizationID
			in.Organization = &organization
		}
		return in
	})
	if err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{}
	for name, value := range result.Claims {
		if !slices.Contains(action.ReservedClaims, name) {
			out[name] = value
		}
	}
	return out, nil
}

// hookError is the OAuth error of a hook refusing a token: access_denied
// with the target's message, else temporarily_unavailable.
func hookError(err error) error {
	var e *errx.Error
	if errx.As(err, &e) && e.Code == "ACTION_DENIED" {
		return fosite.ErrAccessDenied.WithHint(e.Message)
	}
	return fosite.ErrTemporarilyUnavailable.WithHint("an action failed")
}

// stringList reads a []string claim back from a decoded session.
func stringList(v any) []string {
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
