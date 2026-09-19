package impersonation

import (
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Request struct {
	Organization identity.OrganizationID `json:"organization_id"`
	Application  identity.ApplicationID  `json:"application_id"`
	Resource     identity.ResourceID     `json:"resource_id"`
	User         identity.UserID         `json:"user_id"`
	Reason       string                  `json:"reason"`
}

func (r Request) Validate() error {
	if r.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if r.Application.IsZero() {
		return errx.Validation("application_id must be a valid UUID")
	}
	if r.Resource.IsZero() {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if r.User.IsZero() {
		return errx.Validation("user_id must be a valid UUID")
	}
	reason := strings.TrimSpace(r.Reason)
	if len(reason) < 10 || len(r.Reason) > 1000 {
		return errx.Validation("reason must be 10-1000 characters")
	}
	return nil
}

type Target struct {
	Context authentication.Context
	User    identity.UserID
	Reason  string
	Actor   identity.OperatorID
	Session identity.SessionID
	Expires time.Time
}
