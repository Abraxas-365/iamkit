package impersonation

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"time"
)

type Request struct {
	Organization string `json:"organization_id"`
	Application  string `json:"application_id"`
	Resource     string `json:"resource_id"`
	User         string `json:"user_id"`
	Reason       string `json:"reason"`
}
type Target struct {
	Context                      authentication.Context
	User, Reason, Actor, Session string
	Expires                      time.Time
}
type Commands interface {
	Create(context.Context, management.Principal, string, Request) (authentication.Token, string, error)
}

type Repository interface {
	Create(context.Context, Target) (authentication.Access, error)
}
