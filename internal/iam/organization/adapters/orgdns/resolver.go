// Package orgdns resolves DNS TXT records for organization domain verification.
package orgdns

import (
	"context"
	"errors"
	"net"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
)

// Resolver uses the system resolver unless Lookup is set.
type Resolver struct {
	Lookup *net.Resolver
}

var _ organization.Resolver = Resolver{}

func (r Resolver) TXT(ctx context.Context, name string) ([]string, error) {
	lookup := r.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, config.ExternalHTTPTimeout)
	defer cancel()
	records, err := lookup.LookupTXT(ctx, name)
	var dns *net.DNSError
	if errors.As(err, &dns) && dns.IsNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, errx.Wrap(err, "DNS lookup failed, retry later", errx.TypeExternal)
	}
	return records, nil
}
