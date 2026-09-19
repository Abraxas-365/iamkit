// Package authmodule assembles authentication sessions, tokens and HTTP adapters.
package authmodule

import (
	"context"
	"crypto/rsa"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authjwt"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB           *sqlx.DB
	Key          *rsa.PrivateKey
	Issuer       string
	Delivery     authentication.Delivery
	IssueSession func(*fiber.Ctx, authentication.Issued) error
}
type Module struct {
	Commands        authentication.Commands
	Validator       authentication.TokenValidator
	Tokens          *authhttp.Tokens
	HTTP            *authhttp.Handler
	Sessions        federation.Sessions
	DeliveryService *authsvc.DeliveryService
}
type federationSessions struct{ service *authsvc.Service }

func (s federationSessions) NewSession(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID) (authentication.Issued, error) {
	return s.service.NewSession(ctx, tx, boundary, user)
}
func New(deps Deps) Module {
	repo := authpg.New(deps.DB)
	service := authsvc.New(repo, authbcrypt.Hasher{}, authsecret.Generator{}, deps.Delivery)
	deliveryRepo := authpg.NewDeliveryConfigRepository(deps.DB)
	factory := func(url, token string) authentication.Delivery {
		return authmail.WebhookDelivery{URL: url, Token: token}
	}
	deliverySvc := authsvc.NewDeliveryService(deliveryRepo, deps.Delivery, factory)
	service.SetDeliveryService(deliverySvc)
	tokens := authsvc.NewTokens(repo, authjwt.New(deps.Key, deps.Issuer), authsecret.Generator{})
	return Module{Commands: service, Validator: tokens, Tokens: authhttp.NewTokens(tokens, tokens, tokens, tokens), HTTP: authhttp.New(service, deps.IssueSession), Sessions: federationSessions{service}, DeliveryService: deliverySvc}
}
