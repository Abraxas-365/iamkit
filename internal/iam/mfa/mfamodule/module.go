// Package mfamodule assembles multi-factor authentication.
package mfamodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfahttp"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfapg"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfatotp"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/mfasvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB     *sqlx.DB
	Cipher mfa.Cipher // IAMKIT_ENCRYPTION_KEY; enrollment fails without it
	Clock  mfa.Clock  // nil uses time.Now
	// Validate checks user access tokens of the self-service routes.
	Validate mfahttp.Validate
	ActorID  func(*fiber.Ctx) string
}

type Module struct {
	Commands     mfa.Commands
	Queries      mfa.Queries
	Logins       mfa.Logins
	SecondFactor authentication.SecondFactor
	HTTP         *mfahttp.Handler
}

func New(deps Deps) Module {
	service := mfasvc.New(mfapg.New(deps.DB), mfatotp.TOTP{}, deps.Cipher, mgmtsecret.Generator{}, deps.Clock)
	return Module{Commands: service, Queries: service, Logins: service, SecondFactor: service, HTTP: mfahttp.New(service, service, deps.Validate, deps.ActorID)}
}
