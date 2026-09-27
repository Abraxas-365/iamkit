// Package netx guards outbound connections to operator-supplied hosts
// (identity providers, email providers) so they cannot reach internal
// addresses.
package netx

import (
	"errors"
	"net"
	"syscall"

	"github.com/Abraxas-365/iamkit/internal/config"
)

// ErrNotPublic is returned by a guarded dial to a non-public address. It is
// a plain error: callers classify it (a misconfigured provider, not an
// unauthorized caller).
var ErrNotPublic = errors.New("address is not public")

var sharedAddressSpace = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// Public reports whether ip is a globally routable unicast address.
func Public(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !sharedAddressSpace.Contains(ip)
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
