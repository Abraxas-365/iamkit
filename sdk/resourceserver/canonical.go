package resourceserver

import (
	"errors"
	"strconv"
	"strings"
)

// maxResourceURI bounds a resource indicator.
const maxResourceURI = 2048

// ErrInvalidResource is returned for a resource URI that has no canonical
// form.
var ErrInvalidResource = errors.New("resource must be an absolute https URI (http only on localhost, 127.0.0.1 or [::1]) without userinfo, query, fragment or dot segments")

// CanonicalResource is the canonical form of an RFC 8707 resource
// indicator, the same rule IAMKit applies (shared vectors in
// testdata/canonical.json): an absolute https URI (http only on localhost,
// 127.0.0.1 or [::1]), scheme and host lowercased, the default port
// dropped, no userinfo, query or fragment, no "." / ".." or empty path
// segments and no trailing slash. Path case and percent-encoding are kept.
func CanonicalResource(raw string) (string, error) {
	if raw == "" || len(raw) > maxResourceURI {
		return "", ErrInvalidResource
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] >= 0x7f {
			return "", ErrInvalidResource
		}
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	scheme = strings.ToLower(scheme)
	if !ok || (scheme != "https" && scheme != "http") || strings.ContainsAny(rest, "?#") {
		return "", ErrInvalidResource
	}
	authority, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	host, port, ok := splitAuthority(authority)
	if !ok {
		return "", ErrInvalidResource
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if scheme == "http" && host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
		return "", ErrInvalidResource
	}
	if path, ok = canonicalPath(path); !ok {
		return "", ErrInvalidResource
	}
	out := scheme + "://" + host
	if port != "" {
		out += ":" + port
	}
	return out + path, nil
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
