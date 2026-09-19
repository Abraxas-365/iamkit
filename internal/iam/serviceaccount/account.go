package serviceaccount

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Input struct {
	Name        string   `json:"name"`
	Application string   `json:"application_id"`
	Resource    string   `json:"resource_id"`
	Permissions []string `json:"permissions"`
	ExpiresIn   *string  `json:"expires_in,omitempty"`
}

// Validate checks the structural invariants Input owns. Permission catalog
// membership is enforced separately in the service.
func (i Input) Validate() error {
	if strings.TrimSpace(i.Name) == "" {
		return errx.Validation("service account name is required")
	}
	if !identity.ValidID(i.Application) {
		return errx.Validation("application_id must be a valid UUID")
	}
	if !identity.ValidID(i.Resource) {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if err := identity.ValidatePermissions(i.Permissions, ""); err != nil {
		return err
	}
	return nil
}

type Credential struct {
	ID      string    `json:"id"`
	Secret  string    `json:"secret"`
	Expires time.Time `json:"expires_at"`
}
type Account struct {
	ID              string     `json:"id" db:"id"`
	Name            string     `json:"name" db:"name"`
	Application     string     `json:"application_id" db:"application_id"`
	ApplicationName string     `json:"application_name" db:"application_name"`
	Resource        string     `json:"resource_id" db:"resource_id"`
	ResourceName    string     `json:"resource_name" db:"resource_name"`
	Permissions     []string   `json:"permissions" db:"permissions"`
	Expires         time.Time  `json:"expires_at" db:"expires_at"`
	Revoked         *time.Time `json:"revoked_at" db:"revoked_at"`
}
