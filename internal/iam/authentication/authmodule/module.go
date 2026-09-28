// Package authmodule assembles authentication sessions, tokens and HTTP adapters.
package authmodule

import (
	"context"
	"crypto/rsa"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authjwt"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB           *sqlx.DB
	Key          *rsa.PrivateKey
	Issuer       string
	Delivery     authentication.Delivery
	OAuthTokens  authentication.OAuthTokens // nil rejects every OAuth-issued access token
	IssueSession func(*fiber.Ctx, authentication.Issued) error
	SecondFactor authentication.SecondFactor // nil disables MFA
	Cipher       authentication.Cipher       // seals delivery secrets; nil refuses to store them
	// Mail configures how emails IAMKit renders are written and sent.
	Mail Mail
}

// Mail configures rendered email: the deployment default language, the
// deployment-wide SMTP/Resend sender (replacing Deps.Delivery), and test
// overrides of how environment SMTP/Resend providers are reached (public
// addresses only by default).
type Mail struct {
	Locale         string
	Global         *Sender
	Dial           func(ctx context.Context, network, address string) (net.Conn, error)
	ResendEndpoint string
	ResendClient   http.RoundTripper
}

// Sender is a deployment-wide email provider IAMKit renders for.
type Sender struct {
	Provider                string // smtp or resend
	Mailer                  authentication.Mailer
	From, FromName, ReplyTo string
}

type Module struct {
	Commands        authentication.Commands
	Authenticator   authentication.Authenticator
	Validator       authentication.TokenValidator
	Tokens          *authhttp.Tokens
	HTTP            *authhttp.Handler
	Sessions        federation.Sessions
	DeliveryService *authsvc.DeliveryService
	// Brand sets where rendered emails read the environment's brand, once
	// the module owning it is built.
	Brand func(authentication.Branding)
}
type federationSessions struct{ service *authsvc.Service }

func (s federationSessions) SignIn(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID, email string, organizationSSO bool) (authentication.Result, error) {
	return s.service.SignInFederated(ctx, tx, boundary, user, email, organizationSSO)
}

// lateBranding is a Branding set after the module is built (the hosted
// module owns branding and is assembled later).
type lateBranding struct {
	b atomic.Pointer[authentication.Branding]
}

func (l *lateBranding) Brand(ctx context.Context, environment identity.EnvironmentID) (authentication.Brand, error) {
	if b := l.b.Load(); b != nil {
		return (*b).Brand(ctx, environment)
	}
	return authentication.Brand{}, nil
}

func New(deps Deps) Module {
	branding := &lateBranding{}
	templates := authpg.NewTemplateRepository(deps.DB)
	renderer := authmail.Renderer{Branding: branding, Templates: authsvc.SavedCopy{Repo: templates}, Locale: deps.Mail.Locale}
	global, globalProvider := deps.Delivery, authentication.ProviderWebhook
	if g := deps.Mail.Global; g != nil {
		global = authmail.Rendered{Renderer: renderer, Mailer: g.Mailer, From: g.From, FromName: g.FromName, ReplyTo: g.ReplyTo}
		globalProvider = g.Provider
	}
	repo := authpg.New(deps.DB)
	service := authsvc.New(repo, authbcrypt.Hasher{}, authsecret.Generator{}, global)
	if deps.SecondFactor != nil {
		service.SetSecondFactor(deps.SecondFactor)
	}
	deliveryRepo := authpg.NewDeliveryConfigRepository(deps.DB)
	factory := func(cfg authentication.DeliveryConfig, secret authentication.DeliverySecret) (authentication.Delivery, error) {
		if cfg.Provider == authentication.ProviderWebhook {
			return authmail.WebhookDelivery{URL: cfg.WebhookURL, Token: secret.WebhookToken}, nil
		}
		plain := ""
		if secret.Sealed != "" {
			if deps.Cipher == nil {
				return nil, authentication.DeliveryFailure(errx.Internal("no cipher to open the delivery secret"), authentication.CodeDeliveryCredential)
			}
			opened, err := deps.Cipher.Open(secret.Sealed)
			if err != nil {
				return nil, authentication.DeliveryFailure(err, authentication.CodeDeliveryCredential)
			}
			plain = string(opened)
		}
		var mailer authentication.Mailer
		switch cfg.Provider {
		case authentication.ProviderSMTP:
			mailer = authmail.SMTP{Host: cfg.SMTPHost, Port: cfg.SMTPPort, TLS: cfg.SMTPTLS, Username: cfg.SMTPUsername, Password: plain, Dial: deps.Mail.Dial}
		case authentication.ProviderResend:
			mailer = authmail.Resend{APIKey: plain, Endpoint: deps.Mail.ResendEndpoint, Transport: deps.Mail.ResendClient}
		default:
			return nil, errx.Internal("unknown email provider " + cfg.Provider)
		}
		return authmail.Rendered{Renderer: renderer, Mailer: mailer, From: cfg.FromEmail, FromName: cfg.FromName, ReplyTo: cfg.ReplyTo}, nil
	}
	deliverySvc := authsvc.NewDeliveryService(deliveryRepo, global, factory, deps.Cipher, deps.Issuer)
	deliverySvc.SetGlobalProvider(globalProvider)
	deliverySvc.SetRenderer(renderer)
	deliverySvc.SetTemplates(templates)
	service.SetDeliveryService(deliverySvc)
	tokens := authsvc.NewTokens(repo, authjwt.New(deps.Key, deps.Issuer), authsecret.Generator{}, deps.OAuthTokens)
	return Module{
		Commands: service, Authenticator: service, Validator: tokens, Tokens: authhttp.NewTokens(tokens, tokens, tokens, tokens),
		HTTP: authhttp.New(service, service, deps.IssueSession), Sessions: federationSessions{service}, DeliveryService: deliverySvc,
		Brand: func(b authentication.Branding) { branding.b.Store(&b) },
	}
}
