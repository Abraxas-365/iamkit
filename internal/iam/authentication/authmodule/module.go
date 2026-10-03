// Package authmodule assembles authentication sessions, tokens and HTTP adapters.
package authmodule

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authjwt"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authsms"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB           *sqlx.DB
	Keys         signing.Keyring // signs and verifies tokens (per-environment keys, deployment key)
	Issuer       string
	Delivery     authentication.Delivery
	OAuthTokens  authentication.OAuthTokens // nil rejects every OAuth-issued access token
	IssueSession func(*fiber.Ctx, authentication.Issued) error
	SecondFactor authentication.SecondFactor // nil disables MFA
	Passkeys     authentication.Passkeys     // nil disables passkey sign-in
	Cipher       authentication.Cipher       // seals delivery secrets; nil refuses to store them
	ActorID      func(*fiber.Ctx) string     // operator of management routes
	// Breaches checks new passwords against known breaches when a policy
	// asks; nil skips the check.
	Breaches authentication.Breaches
	// Actions runs pre_sign_in / pre_registration hooks (nil: none).
	Actions authentication.Actions
	// Usage enforces the users limit on signups and the daily email/SMS
	// limits, and counts tokens, emails and SMS (nil: none).
	Usage authentication.Usage
	// Mail configures how emails IAMKit renders are written and sent.
	Mail Mail
}

// Mail configures rendered email: the deployment default language, the
// deployment-wide SMTP/Resend sender (replacing Deps.Delivery), and test
// overrides of how environment SMTP/Resend/webhook endpoints are reached
// (public addresses only by default).
type Mail struct {
	Locale         string
	Global         *Sender
	Dial           func(ctx context.Context, network, address string) (net.Conn, error)
	ResendEndpoint string
	ResendClient   http.RoundTripper
	WebhookClient  http.RoundTripper
	// SMSClient reaches environment SMS endpoints (default guarded);
	// TwilioEndpoint replaces Twilio's API base (tests).
	SMSClient      http.RoundTripper
	TwilioEndpoint string
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
	// PasswordPolicies is the environment password policy; its Queries
	// include the check other modules run on new passwords.
	PasswordPolicies       authentication.PasswordPolicyQueries
	PasswordPolicyCommands authentication.PasswordPolicyCommands
	PasswordPoliciesHTTP   *authhttp.PasswordPolicyHandler
	// SignInPolicies is the environment sign-in policy.
	SignInPolicies     authentication.SignInPolicyQueries
	SignInPoliciesHTTP *authhttp.SignInPolicyHandler
	// Signups is self-registration (the hosted pages use it too).
	Signups authentication.SignupCommands
	// Passkeys is passkey sign-in; nil when Deps.Passkeys is.
	Passkeys   authentication.PasskeyCommands
	SignupHTTP *authhttp.SignupHandler
	// SMS is the environment's SMS provider (second-factor texts).
	SMS        authentication.SMSCommands
	SMSQueries authentication.SMSQueries
	SMSHTTP    *authhttp.SMSHandler
	// Brand sets where rendered emails read the environment's brand, once
	// the module owning it is built.
	Brand func(authentication.Branding)
	// WaitDeliveries waits for code emails still being sent after their
	// response (shutdown, tests).
	WaitDeliveries func(timeout time.Duration) bool
}
type federationSessions struct{ service *authsvc.Service }

func (s federationSessions) SignIn(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID, email string, organizationSSO bool) (authentication.Result, error) {
	return s.service.SignInFederated(ctx, tx, boundary, user, email, organizationSSO)
}

func (s federationSessions) SocialAllowed(ctx context.Context, boundary authentication.Context) error {
	return s.service.SocialAllowed(ctx, boundary)
}

// lateBranding is a Branding set after the module is built (the hosted
// module owns branding and is assembled later).
type lateBranding struct {
	b atomic.Pointer[authentication.Branding]
}

func (l *lateBranding) Brand(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (authentication.Brand, error) {
	if b := l.b.Load(); b != nil {
		return (*b).Brand(ctx, environment, organization)
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
	if deps.Passkeys != nil {
		service.SetPasskeys(deps.Passkeys)
	}
	policies := authsvc.NewPasswordPolicies(authpg.NewPasswordPolicyRepository(deps.DB), deps.Breaches)
	service.SetPasswordPolicies(policies)
	signIns := authsvc.NewSignInPolicies(authpg.NewSignInPolicyRepository(deps.DB))
	service.SetSignInPolicies(signIns)
	service.SetSignups(repo)
	if deps.Actions != nil {
		service.SetActions(deps.Actions)
	}
	deliveryRepo := authpg.NewDeliveryConfigRepository(deps.DB)
	factory := func(cfg authentication.DeliveryConfig, secret authentication.DeliverySecret) (authentication.Delivery, error) {
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
		if cfg.Provider == authentication.ProviderWebhook {
			// Sealed since the token is encrypted at rest; plaintext in
			// rows saved without a key (or before).
			if secret.WebhookToken != "" {
				plain = secret.WebhookToken
			}
			return authmail.WebhookDelivery{URL: cfg.WebhookURL, Token: plain, Transport: deps.Mail.WebhookClient}, nil
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
	sms := authsvc.NewSMSService(authpg.NewSMSRepository(deps.DB), authsvc.SMSFactory(authsms.Factory(deps.Mail.SMSClient, deps.Mail.TwilioEndpoint)), deps.Cipher, branding, deps.Mail.Locale)
	tokens := authsvc.NewTokens(repo, authjwt.New(deps.Keys, deps.Issuer), authsecret.Generator{}, deps.OAuthTokens)
	if deps.Usage != nil {
		service.SetUsage(deps.Usage)
		deliverySvc.SetUsage(deps.Usage)
		sms.SetUsage(deps.Usage)
		tokens.SetUsage(deps.Usage)
	}
	var passkeys authentication.PasskeyCommands
	if deps.Passkeys != nil {
		passkeys = service
	}
	return Module{
		Passkeys: passkeys,
		Commands: service, Authenticator: service, Validator: tokens, Tokens: authhttp.NewTokens(tokens, tokens, tokens, tokens),
		HTTP: authhttp.New(service, service, service, deps.IssueSession), Sessions: federationSessions{service}, DeliveryService: deliverySvc,
		PasswordPolicies: policies, PasswordPolicyCommands: policies, PasswordPoliciesHTTP: authhttp.NewPasswordPolicyHandler(policies, policies, deps.ActorID),
		SignInPolicies: signIns, SignInPoliciesHTTP: authhttp.NewSignInPolicyHandler(signIns, signIns, deps.ActorID),
		Signups: service, SignupHTTP: authhttp.NewSignupHandler(service),
		SMS: sms, SMSQueries: sms, SMSHTTP: authhttp.NewSMSHandler(sms, sms, deps.ActorID),
		Brand:          func(b authentication.Branding) { branding.b.Store(&b) },
		WaitDeliveries: service.WaitDeliveries,
	}
}
