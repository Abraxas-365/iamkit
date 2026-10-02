package oauth

import (
	"net/url"
	"slices"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// MaxOrigins bounds the allowed origins of one client.
const MaxOrigins = 20

// Origins validates and normalizes allowed_origins: each value is a
// browser origin, scheme://host[:port] lowercased without a default port,
// path, query or credentials. HTTPS only, except http on a loopback host
// (local development). Duplicates collapse; nil stays nil.
func Origins(values []string) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) > MaxOrigins {
		return nil, errx.Validation("allowed_origins accepts at most 20 origins")
	}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		origin, ok := normalizeOrigin(raw)
		if !ok {
			return nil, errx.Validation("allowed_origins must be origins like https://app.example.com (http only for localhost)")
		}
		if !slices.Contains(out, origin) {
			out = append(out, origin)
		}
	}
	return out, nil
}

func normalizeOrigin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", false
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if host == "" || strings.Contains(host, "*") {
		return "", false
	}
	switch scheme {
	case "https":
		if port == "443" {
			port = ""
		}
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", false
		}
		if port == "80" {
			port = ""
		}
	default:
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, true
}
