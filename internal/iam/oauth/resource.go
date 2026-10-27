package oauth

import (
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// maxResourceURI bounds a resource indicator.
const maxResourceURI = 2048

// CanonicalResource is the canonical form of an RFC 8707 resource
// indicator (a protected resource's URI): an absolute https URI (http only
// on localhost, 127.0.0.1 or [::1]), scheme and host lowercased, the
// default port dropped, no userinfo, query or fragment, no "." / ".." or
// empty path segments, and no trailing slash ("https://a.example/" is
// "https://a.example"). Path case and percent-encoding are kept as given.
//
// The same rule (and the same test vectors,
// sdk/resourceserver/testdata/canonical.json) runs in sdk/resourceserver
// and @iamkit/node/resource-server: a token's aud and the URI a resource
// server checks are compared after it.
func CanonicalResource(raw string) (string, error) {
	invalid := errx.Validation("resource must be an absolute https URI (http only on localhost, 127.0.0.1 or [::1]) without userinfo, query, fragment or dot segments")
	if raw == "" || len(raw) > maxResourceURI {
		return "", invalid
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] >= 0x7f {
			return "", invalid
		}
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	scheme = strings.ToLower(scheme)
	if !ok || (scheme != "https" && scheme != "http") || strings.ContainsAny(rest, "?#") {
		return "", invalid
	}
	authority, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	host, port, ok := splitAuthority(authority)
	if !ok {
		return "", invalid
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if scheme == "http" && host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
		return "", invalid
	}
	path, ok = canonicalPath(path)
	if !ok {
		return "", invalid
	}
	out := scheme + "://" + host
	if port != "" {
		out += ":" + port
	}
	return out + path, nil
}

// SameResource reports whether two resource indicators name the same
// resource (equal canonical forms; an invalid one never matches).
func SameResource(a, b string) bool {
	ca, err := CanonicalResource(a)
	if err != nil {
		return false
	}
	cb, err := CanonicalResource(b)
	return err == nil && ca == cb
}

func splitAuthority(authority string) (host, port string, ok bool) {
	if authority == "" || strings.Contains(authority, "@") {
		return "", "", false
	}
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", "", false
		}
		host, rest := strings.ToLower(authority[:end+1]), authority[end+1:]
		for _, c := range host[1 : len(host)-1] {
			if !(c == ':' || c == '.' || isHex(byte(c))) {
				return "", "", false
			}
		}
		if len(host) == 2 {
			return "", "", false
		}
		if rest == "" {
			return host, "", true
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", false
		}
		port, ok = validPort(rest[1:])
		return host, port, ok
	}
	host, port, hasPort := strings.Cut(authority, ":")
	host = strings.ToLower(host)
	if host == "" || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return "", "", false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return "", "", false
		}
	}
	if !hasPort {
		return host, "", true
	}
	port, ok = validPort(port)
	return host, port, ok
}

func validPort(port string) (string, bool) {
	if port == "" || port[0] == '0' {
		return "", false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return "", false
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return port, true
}

func canonicalPath(path string) (string, bool) {
	if path == "" || path == "/" {
		return "", true
	}
	path = strings.TrimSuffix(path, "/")
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "" {
			return "", false
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			switch {
			case c == '%':
				if i+2 >= len(segment) || !isHex(segment[i+1]) || !isHex(segment[i+2]) {
					return "", false
				}
				i += 2
			case !isPathChar(c):
				return "", false
			}
		}
		if dot := strings.ReplaceAll(strings.ToLower(segment), "%2e", "."); dot == "." || dot == ".." {
			return "", false
		}
	}
	return path, true
}

// isPathChar: RFC 3986 pchar without pct-encoded.
func isPathChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~!$&'()*+,;=:@", c) >= 0
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
