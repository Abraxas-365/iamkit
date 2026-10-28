package oauth

import "net/url"

// WithIssuer adds the RFC 9207 iss parameter to an authorization response
// redirect (location): every answer at the client's redirect URI, success
// or error, names the authorization server that sent it. Responses use the
// query mode only (ValidateAuthorization), so iss joins the query; a value
// already there is replaced. A location that does not parse is returned
// unchanged.
func WithIssuer(location, issuer string) string {
	target, err := url.Parse(location)
	if err != nil {
		return location
	}
	query := target.Query()
	query.Set("iss", issuer)
	target.RawQuery = query.Encode()
	return target.String()
}
