package authclient

// Profile is the authenticated user's identity.
type Profile struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	EmailVerified  bool   `json:"email_verified"`
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	ActorID        string `json:"actor_id"`
}

// Organization represents a user's organization membership.
type Organization struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Role      string  `json:"role"`
	OrgUnitID *string `json:"org_unit_id"`
	ManagerID *string `json:"manager_id"`
}
