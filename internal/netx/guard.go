// Package netx guards outbound connections to operator-supplied hosts
// (identity providers, email providers) so they cannot reach internal
// addresses.
package netx

import (
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/Abraxas-365/iamkit/internal/config"
)

// ErrNotPublic is returned by a guarded dial to a non-public address. It is
// a plain error: callers classify it (a misconfigured provider, not an
// unauthorized caller).
var ErrNotPublic = errors.New("address is not public")

// reserved are special-purpose ranges that net.IP's predicates still count
// as global unicast (IANA special-purpose registries).
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, broadcast
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/32"),       // Teredo (embeds an arbitrary IPv4)
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

// Public reports whether ip is a globally routable unicast address. IPv6
// forms that embed an IPv4 address (NAT64, 6to4) are judged by that
// address, so they cannot be used to reach internal IPv4 hosts.
func Public(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(addr) {
			return false
		}
	}
	switch b := addr.As16(); {
	case nat64.Contains(addr):
		return Public(net.IP(b[12:16]))
	case sixToFour.Contains(addr):
		return Public(net.IP(b[2:6]))
	}
	return true
}

// GuardedDialer dials only public addresses. The check runs on the resolved
// IP at connect time, so DNS rebinding cannot bypass it.
func GuardedDialer() *net.Dialer {
	return &net.Dialer{Timeout: config.ExternalHTTPTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || !Public(ip) {
			return ErrNotPublic
		}
		return nil
	}}
}
