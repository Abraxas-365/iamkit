package identity

import (
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// ValidateIssuer requires HTTPS except on explicit loopback hosts for local
// development. Issuers cannot contain credentials, queries or fragments.
func ValidateIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Scheme != "https" && !LoopbackHTTP(u)) {
		return errx.Validation("issuer must be an absolute HTTPS URL (HTTP allowed only on localhost, 127.0.0.1 or [::1]) without credentials, query or fragment")
	}
	return nil
}
