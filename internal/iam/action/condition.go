package action

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Conditions. function:* hook the sign-in and token flows; request:* the
// allow-listed management requests.
const (
	PreSignIn       = "function:pre_sign_in"
	PreRegistration = "function:pre_registration"
	PostFederation  = "function:post_federation"
	PreAccessToken  = "function:pre_access_token"
	PreIDToken      = "function:pre_id_token"
	PreUserInfo     = "function:pre_userinfo"
	UserCreate      = "request:user.create"
	UserUpdate      = "request:user.update"
	MembershipAdd   = "request:membership.create"
)

// Condition describes what a condition's targets may answer.
type Condition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Deny: a call target may refuse the flow.
	Deny bool `json:"deny"`
	// Claims: a call target may add token (or UserInfo) claims.
	Claims bool `json:"claims"`
	// Patch names the input fields a call target may replace.
	Patch []string `json:"patch,omitempty"`
}

// Conditions is the catalog, in display order.
var Conditions = []Condition{
	{Name: PreSignIn, Description: "Before a user session is created (every sign-in method)", Deny: true},
	{Name: PreRegistration, Description: "Before a self-service signup or a federated first sign-in creates a user", Deny: true},
	{Name: PostFederation, Description: "After an external identity provider verified a user, before the account is linked", Deny: true, Patch: []string{"name"}},
	{Name: PreAccessToken, Description: "Before an OAuth access token is issued (also on refresh)", Deny: true, Claims: true},
	{Name: PreIDToken, Description: "Before an OIDC ID token is issued", Deny: true, Claims: true},
	{Name: PreUserInfo, Description: "Before /oauth/userinfo answers", Claims: true},
	{Name: UserCreate, Description: "Before the management API creates a user", Deny: true, Patch: []string{"name", "username", "avatar_url"}},
	{Name: UserUpdate, Description: "Before the management API updates a user", Deny: true, Patch: []string{"name", "avatar_url"}},
	{Name: MembershipAdd, Description: "Before the management API adds a user to an organization", Deny: true},
}

// FindCondition returns the condition called name.
func FindCondition(name string) (Condition, bool) {
	for _, c := range Conditions {
		if c.Name == name {
			return c, true
		}
	}
	return Condition{}, false
}

// Input is what a target receives (the webhook body): the condition, the
// environment and what the flow knows. Fields a condition does not have
// are omitted.
type Input struct {
	Condition    string                   `json:"condition"`
	Environment  identity.EnvironmentID   `json:"environment_id"`
	Organization *identity.OrganizationID `json:"organization_id,omitempty"`
	Application  *identity.ApplicationID  `json:"application_id,omitempty"`
	Client       string                   `json:"client_id,omitempty"`
	User         *UserInput               `json:"user,omitempty"`
	// Method is how the user signed in (amr values).
	Method []string `json:"amr,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	// Identity is the external identity of post_federation and federated
	// pre_registration.
	Identity *IdentityInput `json:"identity,omitempty"`
	// Request is the body of a request:* condition.
	Request json.RawMessage `json:"request,omitempty"`
}

// UserInput is the user a flow is about.
type UserInput struct {
	ID       *identity.UserID `json:"id,omitempty"`
	Email    string           `json:"email,omitempty"`
	Name     string           `json:"name,omitempty"`
	Username string           `json:"username,omitempty"`
}

// IdentityInput is an external identity a provider verified.
type IdentityInput struct {
	Connection identity.ConnectionID `json:"connection_id"`
	Provider   string                `json:"provider"`
	Subject    string                `json:"subject"`
	Email      string                `json:"email,omitempty"`
	Name       string                `json:"name,omitempty"`
}

// Response is what a call target answers (an empty body = allow).
type Response struct {
	// Deny refuses the flow with Message (shown to the user).
	Deny    bool   `json:"deny,omitempty"`
	Message string `json:"message,omitempty"`
	// Claims are added to the token (or UserInfo response).
	Claims map[string]json.RawMessage `json:"claims,omitempty"`
	// Patch replaces input fields the condition lets targets change.
	Patch map[string]json.RawMessage `json:"patch,omitempty"`
}

// Result is what the targets of a condition decided, merged in order.
type Result struct {
	Claims map[string]json.RawMessage
	Patch  map[string]string
}

// Claim names reserved by the tokens IAMKit issues; a target cannot set them.
var ReservedClaims = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "auth_time", "nonce", "acr", "amr", "azp", "at_hash", "c_hash", "sid", "act", "scope", "scp", "client_id",
	"environment_id", "organization_id", "application_id", "resource_id", "permissions", "purpose", "oauth_client_id", "token_use", "token_type", "cnf", "may_act"}

// claimName: a plain or namespaced (URL-style) claim name.
var claimName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:/-]{0,127}$`)

// Check validates a call target's answer for condition: denial only where
// the condition allows it (with a short message), unreserved claims within
// config.ActionMaxClaims, string patches of allowed fields.
func (r Response) Check(condition Condition) error {
	if r.Deny {
		if !condition.Deny {
			return errx.Validation("this condition cannot be denied")
		}
		if n := len([]rune(strings.TrimSpace(r.Message))); n > MaxDenyMessage {
			return errx.Validation("message must be at most 200 characters")
		}
		return nil
	}
	if len(r.Claims) > 0 {
		if !condition.Claims {
			return errx.Validation("this condition takes no claims")
		}
		raw, _ := json.Marshal(r.Claims)
		if len(raw) > config.ActionMaxClaims {
			return errx.Validation("claims must encode to at most 4 KiB")
		}
		for name, value := range r.Claims {
			if !claimName.MatchString(name) || slices.Contains(ReservedClaims, name) {
				return errx.Validation("claim " + name + " is reserved or invalid")
			}
			if !json.Valid(value) {
				return errx.Validation("claim " + name + " is not JSON")
			}
		}
	}
	for field, value := range r.Patch {
		if !slices.Contains(condition.Patch, field) {
			return errx.Validation("field " + field + " cannot be patched here")
		}
		var s string
		if json.Unmarshal(value, &s) != nil {
			return errx.Validation("patch of " + field + " must be a string")
		}
	}
	return nil
}

// Merge adds a later target's claims and patches over the earlier ones.
func (r *Result) Merge(response Response) {
	for name, value := range response.Claims {
		if r.Claims == nil {
			r.Claims = map[string]json.RawMessage{}
		}
		r.Claims[name] = value
	}
	for field, value := range response.Patch {
		if r.Patch == nil {
			r.Patch = map[string]string{}
		}
		var s string
		_ = json.Unmarshal(value, &s) // checked
		r.Patch[field] = s
	}
}

// ClaimValues decodes the claims for a token's claim map.
func (r Result) ClaimValues() map[string]any {
	out := make(map[string]any, len(r.Claims))
	for name, raw := range r.Claims {
		var v any
		if json.Unmarshal(raw, &v) == nil {
			out[name] = v
		}
	}
	return out
}

// DenyMessage is the message a denial shows ("" = a generic one).
func (r Response) DenyMessage() string {
	if m := strings.TrimSpace(r.Message); m != "" {
		return m
	}
	return "Access was denied by a policy of this application"
}
