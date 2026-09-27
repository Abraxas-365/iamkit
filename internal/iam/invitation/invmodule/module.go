// Package invmodule assembles invitation use cases and HTTP adapter.
package invmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation/adapters/invhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation/adapters/invmail"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation/adapters/invpg"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation/invsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Delivery sends invitation mail; nil skips delivery (the operator gets
	// the token in the response).
	Delivery invmail.Sender
	ActorID  func(*fiber.Ctx) string
}

type Module struct {
	Commands invitation.Commands
	Queries  invitation.Queries
	HTTP     *invhttp.Handler
}

func New(deps Deps) Module {
	var mailer invitation.Mailer
	if deps.Delivery != nil {
		mailer = invmail.Mailer{Sender: deps.Delivery}
	}
	service := invsvc.New(invpg.New(deps.DB), mgmtsecret.Generator{}, authbcrypt.Hasher{}, mailer, nil)
	return Module{Commands: service, Queries: service, HTTP: invhttp.New(service, service, deps.ActorID)}
}
