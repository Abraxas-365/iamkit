package authclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/golang-jwt/jwt/v5"
)

// KeyLogin signs a machine user in with one of its keys (RFC 7523
// JWT-bearer grant, no OAuth client involved).
type KeyLogin struct {
	baseURL string
	user    string
	kid     string
	key     crypto.Signer
	method  jwt.SigningMethod
	http    *http.Client
}

// KeyBoundary is where the session opens: the organization, application
// and resource of the token, as for any sign-in. EnvironmentID is optional
// (the key's environment).
type KeyBoundary struct {
	EnvironmentID  string
	OrganizationID string
	ApplicationID  string
	ResourceID     string
}

// NewKeyLogin prepares key logins for machine user user with key kid (the
// key's ID). key is its private half: an *rsa.PrivateKey (signed RS256) or
// an *ecdsa.PrivateKey (ES256/384/512 by curve). Use ParsePrivateKey for
// the PEM IAMKit returns when it generates the pair.
func NewKeyLogin(baseURL, user, kid string, key crypto.Signer, opts ...OAuthOption) (*KeyLogin, error) {
	var method jwt.SigningMethod
	switch k := key.(type) {
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			method = jwt.SigningMethodES256
		case 384:
			method = jwt.SigningMethodES384
		case 521:
			method = jwt.SigningMethodES512
		}
	}
	if method == nil {
		return nil, &apierror.Error{Code: "VALIDATION", Message: "key must be an RSA or EC (P-256, P-384, P-521) private key", HTTPStatus: 400}
	}
	holder := &OAuthClient{}
	for _, o := range opts {
		o(holder)
	}
	return &KeyLogin{baseURL: strings.TrimRight(baseURL, "/"), user: user, kid: kid, key: key, method: method, http: holder.http}, nil
}

// ParsePrivateKey reads a PEM private key (PKCS #8, PKCS #1 or SEC 1).
func ParsePrivateKey(pemKey []byte) (crypto.Signer, error) {
	invalid := &apierror.Error{Code: "VALIDATION", Message: "not a PEM RSA or EC private key", HTTPStatus: 400}
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, invalid
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, invalid
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, invalid
}

// Assertion is a fresh one-minute assertion for this issuer's token
// endpoint (each is accepted once).
func (k *KeyLogin) Assertion() (string, error) {
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", err
	}
	now := time.Now()
	token := jwt.NewWithClaims(k.method, jwt.RegisteredClaims{Issuer: k.user, Subject: k.user, Audience: jwt.ClaimStrings{k.baseURL + "/oauth/token"}, ID: base64.RawURLEncoding.EncodeToString(jti[:]), IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))})
	token.Header["kid"] = k.kid
	return token.SignedString(k.key)
}

// Token signs a fresh assertion and trades it for an application access
// token in boundary (no refresh token: sign again when it expires).
// Failures are *OAuthError (invalid_grant for any refused assertion).
func (k *KeyLogin) Token(ctx context.Context, boundary KeyBoundary) (TokenPair, error) {
	var out TokenPair
	assertion, err := k.Assertion()
	if err != nil {
		return out, err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion},
		"organization_id": {boundary.OrganizationID}, "application_id": {boundary.ApplicationID}, "resource_id": {boundary.ResourceID}}
	if boundary.EnvironmentID != "" {
		form.Set("environment_id", boundary.EnvironmentID)
	}
	err = (&OAuthClient{baseURL: k.baseURL, http: k.http}).send(ctx, "token", form, false, &out)
	return out, err
}
