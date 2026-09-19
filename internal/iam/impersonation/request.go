package impersonation

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Request struct {
	Organization string `json:"organization_id"`
	Application  string `json:"application_id"`
	Resource     string `json:"resource_id"`
	User         string `json:"user_id"`
	Reason       string `json:"reason"`
}

// Validate checks the structural invariants Request owns.
func (r Request) Validate() error {
	if !identity.ValidID(r.Organization) {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if !identity.ValidID(r.Application) {
		return errx.Validation("application_id must be a valid UUID")
	}
	if !identity.ValidID(r.Resource) {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if !identity.ValidID(r.User) {
		return errx.Validation("user_id must be a valid UUID")
	}
	reason := strings.TrimSpace(r.Reason)
	if len(reason) < 10 || len(r.Reason) > 1000 {
		return errx.Validation("reason must be 10-1000 characters")
	}
	return nil
}

type Target struct {
	Context                      authentication.Context
	User, Reason, Actor, Session string
	Expires                      time.Time
}
