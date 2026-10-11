package identity

import (
	"context"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxUserAgent is how many characters of a User-Agent are kept.
const MaxUserAgent = 512

// ClientInfo describes the HTTP client behind a request: its address and
// User-Agent. It travels in the request context (WithClientInfo) so the
// writers of sessions can record where a session was opened without every
// caller passing it down. The zero value means "not an HTTP request".
type ClientInfo struct {
	IP        string
	UserAgent string
}

type clientInfoKey struct{}

// NewClientInfo normalizes what a request says about its client: an
// address that does not parse is dropped; the User-Agent loses invalid
// UTF-8, control characters (NUL, line breaks, tabs, ANSI escapes) and the
// Unicode bidirectional override and isolate characters, which could forge
// what a session list shows, and is cut to MaxUserAgent characters.
func NewClientInfo(ip, userAgent string) ClientInfo {
	var out ClientInfo
	if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
		out.IP = addr.Unmap().WithZone("").String()
	}
	agent := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return -1
		}
		return r
	}, strings.ToValidUTF8(userAgent, "")))
	if utf8.RuneCountInString(agent) > MaxUserAgent {
		agent = string([]rune(agent)[:MaxUserAgent])
	}
	out.UserAgent = agent
	return out
}

// WithClientInfo returns ctx carrying the client of the request.
func WithClientInfo(ctx context.Context, info ClientInfo) context.Context {
	return context.WithValue(ctx, clientInfoKey{}, info)
}

// ClientInfoFrom returns the client WithClientInfo stored (zero without).
func ClientInfoFrom(ctx context.Context) ClientInfo {
	info, _ := ctx.Value(clientInfoKey{}).(ClientInfo)
	return info
}

// Args are the SQL arguments for the sessions columns ip_address (inet) and
// user_agent: nil (NULL) for what is unknown.
func (i ClientInfo) Args() (ip, userAgent any) {
	if i.IP != "" {
		ip = i.IP
	}
	if i.UserAgent != "" {
		userAgent = i.UserAgent
	}
	return ip, userAgent
}
