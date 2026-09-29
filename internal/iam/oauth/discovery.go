package oauth

import "github.com/Abraxas-365/iamkit/internal/identity"

// Discovery is the OpenID Provider metadata served at
// /.well-known/openid-configuration. Fields are only ever added (existing
// relying parties keep working).
type Discovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// TokenEndpointAuthSigningAlgValuesSupported: private_key_jwt assertions.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	// IntrospectionEndpointAuthMethodsSupported: confidential clients only,
	// with their secret (also those that use private_key_jwt at /oauth/token).
	IntrospectionEndpointAuthMethodsSupported       []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported          []string `json:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                                 []string `json:"scopes_supported"`
	ClaimsSupported                                 []string `json:"claims_supported"`
	CodeChallengeMethodsSupported                   []string `json:"code_challenge_methods_supported"`
	// OpenID Connect Back-Channel Logout 1.0: logout tokens carry sid.
	BackchannelLogoutSupported        bool `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported"`
	// RFC 8628 device authorization grant.
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// NewDiscovery is the metadata for issuer.
func NewDiscovery(issuer string) Discovery {
	return Discovery{
		Issuer:                 issuer,
		AuthorizationEndpoint:  issuer + "/oauth/authorize",
		TokenEndpoint:          issuer + "/oauth/token",
		RevocationEndpoint:     issuer + "/oauth/revoke",
		IntrospectionEndpoint:  issuer + "/oauth/introspect",
		UserinfoEndpoint:       issuer + "/oauth/userinfo",
		EndSessionEndpoint:     issuer + "/oauth/end_session",
		JWKSURI:                issuer + "/.well-known/jwks.json",
		ResponseTypesSupported: []string{"code"},
		// client_credentials: service accounts only (client_id = account id).
		GrantTypesSupported:                             []string{"authorization_code", "refresh_token", "client_credentials", GrantDeviceCode, GrantTokenExchange},
		SubjectTypesSupported:                           []string{"public"},
		IDTokenSigningAlgValuesSupported:                []string{"RS256"},
		TokenEndpointAuthMethodsSupported:               []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported:      identity.AssertionAlgorithms,
		IntrospectionEndpointAuthMethodsSupported:       []string{"client_secret_basic"},
		RevocationEndpointAuthMethodsSupported:          []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		RevocationEndpointAuthSigningAlgValuesSupported: identity.AssertionAlgorithms,
		ScopesSupported:                                 []string{"openid", "profile", "email", "offline_access"},
		ClaimsSupported:                                 []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "sid", "name", "email", "email_verified", "environment_id", "organization_id"},
		CodeChallengeMethodsSupported:                   []string{"S256"},
		BackchannelLogoutSupported:                      true,
		BackchannelLogoutSessionSupported:               true,
		DeviceAuthorizationEndpoint:                     issuer + "/oauth/device_authorization",
	}
}

// UserInfo is the /oauth/userinfo answer: sub always, the rest by the
// token's granted scopes (profile: name; email: email, email_verified).
type UserInfo struct {
	Subject       string `json:"sub"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Environment   string `json:"environment_id"`
	Organization  string `json:"organization_id,omitempty"`
}
