// Package usermodule assembles user persistence, use cases and HTTP entry adapter.
package usermodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userpg"
	"github.com/Abraxas-365/iamkit/internal/iam/user/usersvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB      *sqlx.DB
	ActorID func(*fiber.Ctx) string
	// PasswordPolicy checks new passwords; nil checks only the length.
	PasswordPolicy user.PasswordPolicy
}
type Module struct {
	Commands user.Commands
	Queries  user.Queries
	HTTP     *userhttp.Handler
}

func New(deps Deps) Module {
	service := usersvc.New(userpg.New(deps.DB), authbcrypt.Hasher{})
	if deps.PasswordPolicy != nil {
		service.SetPasswordPolicy(deps.PasswordPolicy)
	}
	return Module{Commands: service, Queries: service, HTTP: userhttp.New(service, service, deps.ActorID)}
}
