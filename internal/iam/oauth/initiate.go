package oauth

import (
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// MaxInitiateLoginURI bounds the stored sign-in endpoint.
const MaxInitiateLoginURI = 2048

// ValidateInitiateLoginURI accepts empty (no third-party initiated login) or
// an absolute https URL — http only on a loopback host — without credentials
// or fragment. A query is allowed: IAMKit keeps it and adds its own
// parameters.
func ValidateInitiateLoginURI(uri string) error {
	if uri == "" {
		return nil
	}
	if len(uri) > MaxInitiateLoginURI || identity.ValidateRedirects([]string{uri}) != nil {
		return errx.Validation("initiate_login_uri must be an absolute HTTPS URL (http only for localhost, 127.0.0.1 or [::1]) without credentials or fragment")
	}
	return nil
}

// InitiateLoginTarget is the client's sign-in endpoint with the parameters
// of a third-party initiated login added (the endpoint's own query is
// kept; IAMKit's parameters replace any with the same name).
func InitiateLoginTarget(endpoint string, params url.Values) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", errx.Validation("initiate_login_uri is invalid")
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
