package identity

import (
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

// Domain normalizes a DNS domain an organization can claim: lowercase ASCII
// (internationalized names become punycode), no trailing dot, no wildcard, at
// least two labels, at most 253 characters and not itself a public suffix
// such as "com", "co.uk" or "github.io".
func Domain(raw string) (string, error) {
	value := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if value == "" {
		return "", errx.Validation("domain is required")
	}
	if strings.Contains(value, "*") {
		return "", errx.Validation("domain must not contain wildcards")
	}
	ascii, err := domainProfile.ToASCII(value)
	if err != nil || len(ascii) > 253 || !strings.Contains(ascii, ".") {
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
