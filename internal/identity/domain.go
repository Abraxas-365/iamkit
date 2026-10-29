package identity

import (
	"net"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var domainProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
)

// DNSHost is the canonical form of a DNS host name: lowercase ASCII
// (internationalized names become punycode), no trailing dot, letters,
// digits, hyphens and dots only, at most 253 characters. IP literals,
// wildcards and anything that is not a valid host name are refused. It is
// the one canonicalizer behind client_id URLs and client allowlist
// origins, so two spellings of a host never name two clients.
func DNSHost(raw string) (string, error) {
	value := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if value == "" {
		return "", errx.Validation("host is required")
	}
	if strings.Contains(value, "*") {
		return "", errx.Validation("host must not contain wildcards")
	}
	if net.ParseIP(strings.Trim(value, "[]")) != nil {
		return "", errx.Validation("host must be a DNS name, not an IP address")
	}
	ascii, err := domainProfile.ToASCII(value)
	if err != nil || len(ascii) > 253 {
		return "", errx.Validation("host must be a valid DNS name such as example.com")
	}
	return ascii, nil
}

// Domain normalizes a DNS domain an organization can claim: DNSHost, with at
// least two labels and not itself a public suffix such as "com", "co.uk" or
// "github.io".
func Domain(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errx.Validation("domain is required")
	}
	ascii, err := DNSHost(raw)
	if err != nil || !strings.Contains(ascii, ".") {
		return "", errx.Validation("domain must be a valid DNS name such as example.com")
	}
	if suffix, _ := publicsuffix.PublicSuffix(ascii); suffix == ascii {
		return "", errx.Validation("domain must not be a public suffix")
	}
	return ascii, nil
}

// EmailDomain returns the ASCII domain of a normalized email address, or ""
// when it has none.
func EmailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return ""
	}
	domain, err := domainProfile.ToASCII(strings.ToLower(email[at+1:]))
	if err != nil {
		return ""
	}
	return domain
}
