package bootstrap

import (
	"net/netip"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// trustedProxies parses IAMKIT_TRUSTED_PROXIES: comma-separated IPs or
// CIDRs of the reverse proxies in front of IAMKit. An invalid entry stops
// start-up rather than silently trusting nothing (or everything).
func trustedProxies(raw string) ([]string, error) {
	entries := list(raw)
	for _, v := range entries {
		if _, err := netip.ParsePrefix(v); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(v); err != nil {
			return nil, errx.Validation("IAMKIT_TRUSTED_PROXIES: " + v + " is not an IP address or CIDR")
		}
	}
	return entries, nil
}
