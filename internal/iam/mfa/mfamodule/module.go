// Package mfamodule assembles multi-factor authentication.
package mfamodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfahttp"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfapg"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfasend"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfatotp"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfawebauthn"
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
	// Issuer is the relying party of security keys and passkeys (its host
	// the RP id, its origin accepted); Origins adds custom sign-in UIs. An
	// issuer on an IP address disables WebAuthn.
	Issuer  string
	Origins []string
}

type Module struct {
	Commands     mfa.Commands
	Queries      mfa.Queries
	Logins       mfa.Logins
	SecondFactor authentication.SecondFactor
	Passkeys     authentication.Passkeys
	HTTP         *mfahttp.Handler
	// Deliver sets how email and SMS codes are sent, once the
	// authentication module is built; until then only TOTP works.
	Deliver func(mail mfasend.Mail, texts mfasend.Texts)
}

func New(deps Deps) Module {
	service := mfasvc.New(mfapg.New(deps.DB), mfatotp.TOTP{}, deps.Cipher, mgmtsecret.Generator{}, deps.Clock)
	relying := mfawebauthn.New(deps.Issuer, deps.Origins)
	service.SetRelying(relying)
	// Without a relying party (issuer on an IP address) nothing offers
	// passkeys.
	var passkeys authentication.Passkeys
	if relying.Enabled() {
		passkeys = service
	}
	return Module{Commands: service, Queries: service, Logins: service, SecondFactor: service, Passkeys: passkeys, HTTP: mfahttp.New(service, service, deps.Validate, deps.ActorID),
		Deliver: func(mail mfasend.Mail, texts mfasend.Texts) {
			service.SetSender(mfasend.Sender{Mail: mail, Texts: texts})
		}}
}
