// Package hostedmodule assembles the hosted sign-in pages.
package hostedmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted/adapters/hostedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted/adapters/hostedpg"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted/hostedsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB             *sqlx.DB
	Authorizations hosted.Authorizations
	Authenticator  authentication.Authenticator
	Challenges     hosted.Challenges
	Federation     hosted.Federation
	Invitations    hosted.Invitations
	SecondFactor   hosted.SecondFactor // nil: no multi-factor step
	// Finish completes the OAuth authorization (oauthhttp.Handler.Finish).
	Finish  hostedhttp.Finisher
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	Flow     hosted.Flow
	Commands hosted.Commands
	Queries  hosted.Queries
	HTTP     *hostedhttp.Handler
}

func New(deps Deps) Module {
	service := hostedsvc.New(hostedpg.New(deps.DB), mgmtsecret.Generator{}, deps.Authorizations, deps.Authenticator, deps.Challenges, deps.Federation, deps.SecondFactor)
	return Module{Flow: service, Commands: service, Queries: service, HTTP: hostedhttp.New(service, service, service, deps.Invitations, deps.Finish, deps.ActorID)}
}
