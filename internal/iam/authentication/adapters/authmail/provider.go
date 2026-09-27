package authmail

import (
	"context"
	"errors"
	"net"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/netx"
)

// networkFailure classifies an error reaching an email provider: a
// refused private address, a timeout, or anything else as unreachable.
// The cause (host, address) stays wrapped, never in the reason.
func networkFailure(err error) error {
	switch {
	case errors.Is(err, netx.ErrNotPublic):
		return authentication.DeliveryFailure(err, authentication.CodeDeliveryAddress)
	case timedOut(err):
		return authentication.DeliveryFailure(err, authentication.CodeProviderTimeout)
	default:
		return authentication.DeliveryFailure(err, authentication.CodeProviderUnreachable)
	}
}

func timedOut(err error) bool {
	var timeout net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout())
}
