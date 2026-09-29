package samlidp

import (
	"slices"
	"strconv"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// PostBinding is the only response binding IAMKit answers with.
const PostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

// MaxIssueDelay is how old an AuthnRequest may be (and how far in the
// future, for clock skew).
const MaxIssueDelay = 90 * time.Second

// AuthnRequest is a decoded (not yet checked) authentication request.
type AuthnRequest struct {
	ID              string
	Issuer          string
	Version         string
	IssueInstant    time.Time
	Destination     string
	ACSURL          string
	ACSIndex        string
	ProtocolBinding string
	RelayState      string
}

// Check validates the request against the identity provider's SSO URL, the
// clock and the service provider it names, and picks the ACS URL the
// response goes to: the requested one when registered, the one at the
// requested index, else the first.
func (r AuthnRequest) Check(ssoURL string, now time.Time, sp ServiceProvider) (Request, error) {
	if r.Version != "2.0" {
		return Request{}, errx.Validation("SAML request version must be 2.0")
	}
	if r.ID == "" || len(r.ID) > 256 {
		return Request{}, errx.Validation("SAML request ID is required")
	}
	if r.Destination != "" && r.Destination != ssoURL {
		return Request{}, errx.Validation("SAML request destination does not match")
	}
	if r.IssueInstant.IsZero() || now.Sub(r.IssueInstant) > MaxIssueDelay || r.IssueInstant.Sub(now) > MaxIssueDelay {
		return Request{}, errx.Validation("SAML request expired")
	}
	if r.ProtocolBinding != "" && r.ProtocolBinding != PostBinding {
		return Request{}, errx.Validation("SAML responses use the HTTP-POST binding")
	}
	if len(r.RelayState) > MaxRelayState {
		return Request{}, errx.Validation("RelayState is too long")
	}
	acs := sp.ACSURLs[0]
	switch {
	case r.ACSURL != "":
		if !slices.Contains(sp.ACSURLs, r.ACSURL) {
			return Request{}, errx.Validation("assertion consumer service URL is not registered")
		}
		acs = r.ACSURL
	case r.ACSIndex != "":
		i, err := strconv.Atoi(r.ACSIndex)
		if err != nil || i < 0 || i >= len(sp.ACSURLs) {
			return Request{}, errx.Validation("assertion consumer service index is not registered")
		}
		acs = sp.ACSURLs[i]
	}
	return Request{ID: r.ID, ServiceProvider: sp.ID, ACSURL: acs, RelayState: r.RelayState}, nil
}

// Target is the application a parked request signs in to.
type Target struct {
	Environment     identity.EnvironmentID
	Application     identity.ApplicationID
	Resource        identity.ResourceID
	ServiceProvider identity.ServiceProviderID
	Name            string
}
