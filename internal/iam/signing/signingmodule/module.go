// Package signingmodule assembles signing-key rotation and the keyring.
package signingmodule

import (
	"crypto/rsa"

	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/iam/signing/adapters/signinghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/signing/adapters/signingpg"
	"github.com/Abraxas-365/iamkit/internal/iam/signing/signingsvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Key is the deployment key (JWT_PRIVATE_KEY_PATH): it signs for every
	// environment without its own active key.
	Key *rsa.PrivateKey
	// Cipher seals environment private keys; Sealing reports whether it
	// can (IAMKIT_ENCRYPTION_KEY set). Without it keys cannot be created.
	Cipher  signing.Cipher
	Sealing func() bool
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	Commands signing.Commands
	Queries  signing.Queries
	Keyring  signing.Keyring
	HTTP     *signinghttp.Handler
}

func New(deps Deps) Module {
	service := signingsvc.New(signingpg.New(deps.DB), deps.Cipher, deps.Sealing, deps.Key)
	return Module{Commands: service, Queries: service, Keyring: service, HTTP: signinghttp.New(service, service, deps.ActorID)}
}
