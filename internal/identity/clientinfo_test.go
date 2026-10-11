package identity

import (
	"context"
	"strings"
	"testing"
	"unicode"
)

func TestNewClientInfo(t *testing.T) {
	if got := NewClientInfo(" 203.0.113.7 ", "  curl/8 "); got.IP != "203.0.113.7" || got.UserAgent != "curl/8" {
		t.Fatalf("plain = %+v", got)
	}
	if got := NewClientInfo("::ffff:203.0.113.7", ""); got.IP != "203.0.113.7" {
		t.Fatalf("mapped v4 = %+v", got)
	}
	if got := NewClientInfo("fe80::1%eth0", ""); got.IP != "fe80::1" {
		t.Fatalf("zone = %+v", got)
	}
	if got := NewClientInfo("not-an-ip", "x"); got.IP != "" || got.UserAgent != "x" {
		t.Fatalf("invalid ip = %+v", got)
	}
	long := NewClientInfo("", strings.Repeat("é", MaxUserAgent+10))
	if n := len([]rune(long.UserAgent)); n != MaxUserAgent {
		t.Fatalf("truncated to %d characters", n)
	}
	if got := NewClientInfo("", "a\x00b\xffc"); got.UserAgent != "abc" {
		t.Fatalf("sanitized = %q", got.UserAgent)
	}
	// Control characters and bidi controls are dropped, then the cap applies
	// to what is left.
	for name, in := range map[string]string{
		"line breaks": "Mozilla\r\n/5.0\t(X11)",
		"ansi escape": "Mozilla\x1b[31m/5.0\x1b[0m(X11)",
		"bidi":        "Mozilla\u202e/5.0\u2066(X11)\u2069\u202a",
		"c1 control":  "Mozilla\u0085/5.0(X11)",
	} {
		got := NewClientInfo("", " "+in+" ").UserAgent
		if strings.ContainsFunc(got, func(r rune) bool {
			return unicode.IsControl(r) || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069'
		}) {
			t.Errorf("%s: %q kept a control or bidi character", name, got)
		}
	}
	if got := NewClientInfo("", "Mozilla\n/5.0\x1b[0m").UserAgent; got != "Mozilla/5.0[0m" {
		t.Fatalf("cleaned = %q", got)
	}
	if got := NewClientInfo("", "\n\u202e \t").UserAgent; got != "" {
		t.Fatalf("only controls = %q", got)
	}
	capped := NewClientInfo("", strings.Repeat("\n", 600)+strings.Repeat("a", MaxUserAgent+5)).UserAgent
	if len(capped) != MaxUserAgent {
		t.Fatalf("cap applies to the cleaned string: %d", len(capped))
	}
}

func TestClientInfoContext(t *testing.T) {
	if got := ClientInfoFrom(context.Background()); got != (ClientInfo{}) {
		t.Fatalf("empty context = %+v", got)
	}
	ctx := WithClientInfo(context.Background(), NewClientInfo("198.51.100.1", "ua"))
	ip, agent := ClientInfoFrom(ctx).Args()
	if ip != "198.51.100.1" || agent != "ua" {
		t.Fatalf("args = %v %v", ip, agent)
	}
	ip, agent = ClientInfo{}.Args()
	if ip != nil || agent != nil {
		t.Fatalf("zero args = %v %v", ip, agent)
	}
}
