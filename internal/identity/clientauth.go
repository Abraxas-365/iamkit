package identity

import (
	"encoding/json"
	"net/url"
	"slices"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// Token endpoint client authentication methods (OAuth 2.0 Dynamic Client
// Registration names).
const (
	AuthNone          = "none"
	AuthSecretBasic   = "client_secret_basic"
	AuthSecretPost    = "client_secret_post"
	AuthPrivateKeyJWT = "private_key_jwt"
)

// AssertionAlgorithms are the JWS algorithms accepted for private_key_jwt
// client assertions (asymmetric only: client_secret_jwt is not offered).
var AssertionAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// maxClientKeys bounds an inline key set.
const maxClientKeys = 10

// ClientAuth is how an OAuth client or a service account authenticates at
// the token endpoint: its secret (HTTP Basic or form body) or a JWT signed
// with one of its keys (RFC 7523), given inline (JWKS) or by URL.
type ClientAuth struct {
	Method     string          `json:"token_endpoint_auth_method"`
	SigningAlg string          `json:"token_endpoint_auth_signing_alg"`
	JWKS       json.RawMessage `json:"jwks,omitempty"`
	JWKSURI    string          `json:"jwks_uri"`
}

// WithDefaults fills the method (none for public clients, else
// client_secret_basic) and the RS256 assertion algorithm; keys given for
// another method stay, so Validate refuses them.
func (a ClientAuth) WithDefaults(public bool) ClientAuth {
	if a.Method == "" {
		a.Method = AuthSecretBasic
		if public {
			a.Method = AuthNone
		}
	}
	if a.SigningAlg == "" {
		a.SigningAlg = "RS256"
	}
	return a
}

// Validate checks a complete (defaulted) configuration. Public clients
// authenticate with none only; private_key_jwt needs exactly one of jwks
// or jwks_uri.
func (a ClientAuth) Validate(public bool) error {
	switch {
	case public && a.Method != AuthNone:
		return errx.Validation("public clients use token_endpoint_auth_method none")
	case !public && !slices.Contains([]string{AuthSecretBasic, AuthSecretPost, AuthPrivateKeyJWT}, a.Method):
		return errx.Validation("token_endpoint_auth_method must be client_secret_basic, client_secret_post or private_key_jwt")
	case !slices.Contains(AssertionAlgorithms, a.SigningAlg):
		return errx.Validation("token_endpoint_auth_signing_alg is not supported")
	}
	if a.Method != AuthPrivateKeyJWT {
		if len(a.JWKS) > 0 || a.JWKSURI != "" {
			return errx.Validation("jwks and jwks_uri need token_endpoint_auth_method private_key_jwt")
		}
		return nil
	}
	if (len(a.JWKS) > 0) == (a.JWKSURI != "") {
		return errx.Validation("private_key_jwt needs either jwks or jwks_uri")
	}
	if a.JWKSURI != "" {
		u, err := url.Parse(a.JWKSURI)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errx.Validation("jwks_uri must be an absolute HTTPS URL")
		}
		return nil
	}
	return ValidatePublicKeys(a.JWKS)
}

// StoredJWKS is the jwks column value: NULL when empty.
func (a ClientAuth) StoredJWKS() any {
	if len(a.JWKS) == 0 || string(a.JWKS) == "null" {
		return nil
	}
	return string(a.JWKS)
}

// ValidatePublicKeys checks the shape of a JSON Web Key Set of public
// signing keys: 1–10 RSA or EC keys, none carrying private material or
// meant for encryption.
func ValidatePublicKeys(raw json.RawMessage) error {
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return errx.Validation("jwks must be a JSON Web Key Set")
	}
	if len(set.Keys) == 0 || len(set.Keys) > maxClientKeys {
		return errx.Validation("jwks must hold between 1 and 10 keys")
	}
	for _, key := range set.Keys {
		kty, _ := key["kty"].(string)
		if kty != "RSA" && kty != "EC" {
			return errx.Validation("jwks keys must be RSA or EC")
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, ok := key[private]; ok {
				return errx.Validation("jwks must hold public keys only")
			}
		}
		if use, ok := key["use"]; ok && use != "sig" {
			return errx.Validation("jwks keys must be signing keys (use sig)")
		}
	}
	return nil
}
