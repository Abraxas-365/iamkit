package impersonation

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
)

type Commands interface {
	Create(ctx context.Context, actor management.Principal, environment string, input Request) (authentication.Token, string, error)
}

type Repository interface {
	Create(ctx context.Context, t Target) (authentication.Access, error)
}
