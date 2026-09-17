package authclient

import (
	"context"
	"net/url"
)

type Profile struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	EmailVerified  bool   `json:"email_verified"`
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	ActorID        string `json:"actor_id"`
}
type Organization struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Role      string  `json:"role"`
	OrgUnitID *string `json:"org_unit_id"`
	ManagerID *string `json:"manager_id"`
}

func (c Client) Profile(ctx context.Context, token, environment, audience string) (Profile, error) {
	var out Profile
	q := url.Values{"environment_id": {environment}, "audience": {audience}}
	err := c.requestMethod(ctx, "GET", "/me?"+q.Encode(), token, nil, &out)
	return out, err
}
func (c Client) UpdateProfile(ctx context.Context, token, environment, audience, name string) error {
	return c.requestMethod(ctx, "PATCH", "/me", token, map[string]string{"environment_id": environment, "audience": audience, "name": name}, nil)
}
func (c Client) Organizations(ctx context.Context, token, environment, audience string) ([]Organization, error) {
	var out []Organization
	q := url.Values{"environment_id": {environment}, "audience": {audience}}
	err := c.requestMethod(ctx, "GET", "/organizations?"+q.Encode(), token, nil, &out)
	return out, err
}
