package authclient

import "context"

// PasswordChanged is the answer of ChangePassword.
type PasswordChanged struct {
	// SessionsRevoked is how many of the user's other sessions ended; the
	// session of the token that asked stays.
	SessionsRevoked int `json:"sessions_revoked"`
}

// ChangePassword changes the signed-in person's own password. The token
// must be an application token of a person (no API key, machine or
// impersonated token) from a recent sign-in: an older one answers 403
// REAUTHENTICATION_REQUIRED. A wrong current password answers 422
// INVALID_CURRENT_PASSWORD (it counts toward the lockout), a new password
// the policy or the breach check refuses 400 PASSWORD_POLICY, and an
// account with no password 422 NO_PASSWORD. The user's other sessions end.
func (c *Client) ChangePassword(ctx context.Context, token, environment, audience, current, next string) (PasswordChanged, error) {
	var out PasswordChanged
	input := struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}{current, next}
	err := c.requestMethod(ctx, "POST", "/me/password?"+sessionQuery(environment, audience), token, input, &out)
	return out, err
}

// SwitchOrganization moves the refresh token's session into another
// organization of the user (boundary names the session's current one) and
// returns tokens for the new session; the old session and refresh token
// end. A target that needs a sign-in the session lacks (enforced single
// sign-on, a second factor, another method) answers 403
// REAUTHENTICATION_REQUIRED with details organization_id and reason
// (sso, mfa or method): sign in again through authorize with that
// organization. No access to the organization is a plain 403.
func (c *Client) SwitchOrganization(ctx context.Context, boundary LoginContext, refresh, organization string) (TokenPair, error) {
	var out TokenPair
	input := struct {
		LoginContext
		Token  string `json:"refresh_token"`
		Switch string `json:"switch_organization_id"`
	}{boundary, refresh, organization}
	err := c.request(ctx, "/refresh", "", input, &out)
	return out, err
}
