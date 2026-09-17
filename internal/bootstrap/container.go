// Package bootstrap is the composition root. Only here are concrete application
// services wired to persistence, cryptography and HTTP adapters.
package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/application/appmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization/authzmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/fedmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation/impmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtpg"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/management/mgmtmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/management/mgmtsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/oauthmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/organization/orgmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning/provmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/sacctmodule"
	"github.com/Abraxas-365/iamkit/internal/iam/user/usermodule"
	"github.com/Abraxas-365/iamkit/internal/server"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func New(db *sqlx.DB, key *rsa.PrivateKey, issuer string, delivery authentication.Delivery) *server.Server {
	managementModule := mgmtmodule.New(mgmtmodule.Deps{DB: db})
	s := &server.Server{Control: managementModule.HTTP, Health: db.PingContext}
	userModule := usermodule.New(usermodule.Deps{DB: db, ActorID: server.OperatorID})
	s.Users = userModule.HTTP
	authenticationModule := authmodule.New(authmodule.Deps{DB: db, Key: key, Issuer: issuer, Delivery: delivery, IssueSession: s.IssueSession})
	s.Tokens = authenticationModule.Tokens
	s.Auth = authenticationModule.HTTP
	organizationModule := orgmodule.New(orgmodule.Deps{DB: db, ActorID: server.OperatorID})
	s.Structure = organizationModule.Structure
	s.Organizations = organizationModule.HTTP
	authorizationModule := authzmodule.New(authzmodule.Deps{DB: db, ActorID: server.OperatorID})
	s.Grants = authorizationModule.Grants
	s.Authorization = authorizationModule.HTTP
	federationModule := fedmodule.New(fedmodule.Deps{DB: db, Issuer: issuer, Sessions: authenticationModule.Sessions, ActorID: server.OperatorID, IssueSession: s.IssueSession})
	s.Federation = federationModule.HTTP
	provisioningModule := provmodule.New(provmodule.Deps{DB: db, ActorID: server.OperatorID})
	s.ProvisioningControl = provisioningModule.Control
	s.Provisioning = provisioningModule.HTTP
	applicationModule := appmodule.New(appmodule.Deps{DB: db, ActorID: server.OperatorID})
	s.Applications = applicationModule.HTTP
	oauthModule := oauthmodule.New(oauthmodule.Deps{DB: db, Key: key, Issuer: issuer, HMACSecret: func() string { return os.Getenv("OIDC_HMAC_SECRET") }, Tokens: s.Tokens, ActorID: server.OperatorID})
	s.OAuth = oauthModule.HTTP
	serviceAccountModule := sacctmodule.New(sacctmodule.Deps{DB: db})
	s.ServiceAccounts = serviceAccountModule.HTTP
	s.Activity = managementModule.Activity
	impersonationModule := impmodule.New(impmodule.Deps{DB: db, Tokens: s.Tokens})
	s.Impersonation = impersonationModule.HTTP
	return s
}
func Management(db *sqlx.DB) *mgmtsvc.Service {
	return mgmtsvc.New(mgmtpg.New(db), mgmtsecret.Generator{})
}
func OpenDatabase() (*sqlx.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errx.Validation("DATABASE_URL is required")
	}
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, errx.Wrap(err, "database connection failed", errx.TypeInternal)
	}
	return db, nil
}
func FromEnvironment(db *sqlx.DB) (*server.Server, error) {
	issuer := os.Getenv("JWT_ISSUER")
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return nil, errx.Validation("JWT_ISSUER must be an HTTPS URL (HTTP allowed only on loopback)")
	}
	data, err := os.ReadFile(os.Getenv("JWT_PRIVATE_KEY_PATH"))
	if err != nil {
		return nil, errx.Wrap(err, "read signing key failed", errx.TypeInternal)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errx.Validation("invalid signing key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, errx.Wrap(e, "invalid signing key", errx.TypeValidation)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errx.Validation("RSA signing key required")
		}
	}
	if key.N.BitLen() < 2048 {
		return nil, errx.Validation("RSA key must be at least 2048 bits")
	}
	var delivery authentication.Delivery
	if os.Getenv("EMAIL_WEBHOOK_URL") != "" {
		mail := authmail.WebhookDelivery{URL: os.Getenv("EMAIL_WEBHOOK_URL"), Token: os.Getenv("EMAIL_WEBHOOK_TOKEN")}
		if err := mail.Validate(); err != nil {
			return nil, err
		}
		delivery = mail
	}
	return New(db, key, strings.TrimSuffix(issuer, "/"), delivery), nil
}
func GenerateKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }
