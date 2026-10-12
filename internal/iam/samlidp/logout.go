package samlidp

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Single logout (SLO) with IAMKit as the identity provider. Opt-in per
// service provider: a registered certificate plus slo_url (the
// application's own LogoutRequests, answered at /saml/:environment/slo)
// and/or slo_soap_url (IAMKit tells the application by SOAP back-channel
// when a session it received an assertion for ends: admin revoke, user
// deactivation, the user's own logout, risk). IAMKit keeps no browser
// session between applications, so an application's logout ends only the
// session its assertion named; there is no front-channel propagation.

// SLO bindings an application's LogoutResponse is sent with.
const (
	SLOBindingRedirect = "redirect"
	SLOBindingPOST     = "post"
)

// Protocol bindings (URNs).
const (
	RedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	SOAPBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
)

// MaxCertificate bounds a registered certificate (PEM).
const MaxCertificate = 16 << 10

// MaxLogoutMessage bounds an inbound SAMLRequest (encoded).
const MaxLogoutMessage = 64 << 10

// Audit actions.
const (
	// ActionLogout: a service provider's LogoutRequest ended the session
	// (actor = the user).
	ActionLogout = "saml.logout"
	// ActionLogoutFailed: a back-channel LogoutRequest gave up after
	// LogoutMaxAttempts.
	ActionLogoutFailed = "saml.logout_failed"
)

// Back-channel delivery.
const (
	LogoutMaxAttempts = 8
	LogoutTimeout     = 10 * time.Second
	// LogoutRetention keeps delivered and failed notifications.
	LogoutRetention = 7 * 24 * time.Hour
	// LogoutBatch is how many due notifications one round claims.
	LogoutBatch = 50
)

// LogoutRetryAfter is the backoff before attempt n+1 (n ≥ 1).
func LogoutRetryAfter(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := 30 * time.Second << min(n-1, 7)
	return min(d, time.Hour)
}

// ValidateLogout checks a provider's single logout settings: URLs are
// absolute HTTPS (or empty), the binding is redirect or post, and a URL
// needs a certificate (a PEM X.509 certificate).
func ValidateLogout(sloURL, binding, soapURL, certificate string) error {
	if binding != SLOBindingRedirect && binding != SLOBindingPOST {
		return errx.Validation("slo_binding must be redirect or post")
	}
	for _, u := range []string{sloURL, soapURL} {
		if u == "" {
			continue
		}
		if len(u) > 2048 || identity.ValidateHTTPS([]string{u}) != nil {
			return errx.Validation("slo_url and slo_soap_url must be absolute HTTPS URLs without credentials or fragments")
		}
	}
	if certificate == "" {
		if sloURL != "" || soapURL != "" {
			return errx.Validation("single logout needs the application's signing certificate")
		}
		return nil
	}
	if _, err := ParseCertificate(certificate); err != nil {
		return err
	}
	return nil
}

// ParseCertificate reads a PEM certificate (one CERTIFICATE block; a bare
// base64 body as metadata carries it is accepted too).
func ParseCertificate(raw string) (*x509.Certificate, error) {
	invalid := errx.Validation("certificate must be a PEM X.509 certificate")
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxCertificate {
		return nil, invalid
	}
	if !strings.HasPrefix(raw, "-----BEGIN") {
		raw = "-----BEGIN CERTIFICATE-----\n" + raw + "\n-----END CERTIFICATE-----"
	}
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, invalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, invalid
	}
	return cert, nil
}

// LogoutMessage is a LogoutRequest as the browser brought it to
// /saml/:environment/slo: HTTP-Redirect (signed over RawQuery) or
// HTTP-POST (signed in the XML).
type LogoutMessage struct {
	Redirect    bool
	SAMLRequest string
	RelayState  string
	RawQuery    string
}

// Validate checks the message's shape before any decoding.
func (m LogoutMessage) Validate() error {
	if m.SAMLRequest == "" {
		return errx.Validation("SAMLRequest is required")
	}
	if len(m.SAMLRequest) > MaxLogoutMessage || len(m.RawQuery) > 2*MaxLogoutMessage {
		return errx.Validation("SAML message is too large")
	}
	if len(m.RelayState) > MaxRelayState {
		return errx.Validation("RelayState is too long")
	}
	return nil
}

// LogoutRequest is a decoded (not yet verified) LogoutRequest.
type LogoutRequest struct {
	ID             string
	Issuer         string
	Destination    string
	NameID         string
	SessionIndexes []string
	IssueInstant   time.Time
	NotOnOrAfter   time.Time
	RelayState     string
}

// Check validates a decoded request against the identity provider's SLO
// URL and the clock.
func (r LogoutRequest) Check(sloURL string, now time.Time) error {
	if r.ID == "" || len(r.ID) > 256 {
		return errx.Validation("SAML request ID is required")
	}
	// SAML bindings 3.4.5.2/3.5.5.2: a signed message names its Destination.
	if r.Destination != sloURL {
		return errx.Validation("SAML request destination does not match")
	}
	if r.IssueInstant.IsZero() || now.Sub(r.IssueInstant) > MaxIssueDelay || r.IssueInstant.Sub(now) > MaxIssueDelay {
		return errx.Validation("SAML request expired")
	}
	if !r.NotOnOrAfter.IsZero() && !now.Before(r.NotOnOrAfter) {
		return errx.Validation("SAML request expired")
	}
	if r.NameID == "" {
		return errx.Validation("SAML logout request has no NameID")
	}
	return nil
}

// IdPSession is a session a service provider received an assertion for
// (saml_idp_sessions).
type IdPSession struct {
	Session         identity.SessionID
	ServiceProvider identity.ServiceProviderID
	Environment     identity.EnvironmentID
	User            identity.UserID
	NameID          string
}

// LogoutNotification is a due back-channel LogoutRequest
// (saml_logout_notifications).
type LogoutNotification struct {
	ID              int64
	Environment     identity.EnvironmentID
	ServiceProvider ServiceProvider
	Session         identity.SessionID
	NameID          string
	Attempts        int
}

// LogoutFlows are the SLO steps (implemented by samlsvc).
type LogoutFlows interface {
	// Logout handles a service provider's LogoutRequest: decoded, its
	// issuer's provider found (single logout configured), signature
	// verified with the provider's certificate, checked; the session the
	// SessionIndex names ends when it was asserted to that provider for
	// that NameID; the signed LogoutResponse (Success, or Requester when
	// nothing matched) goes to the provider's slo_url.
	Logout(ctx context.Context, environment identity.EnvironmentID, m LogoutMessage) (LogoutAnswer, error)
	// DispatchLogouts sends due back-channel LogoutRequests and reports
	// whether more are due.
	DispatchLogouts(ctx context.Context) (bool, error)
	// PruneLogouts deletes old notifications and links of ended sessions.
	PruneLogouts(ctx context.Context) error
}

// LogoutAnswer is the LogoutResponse to deliver through the browser: a
// GET to URL (redirect binding, the message in the query) or an
// auto-submitted POST of Fields.
type LogoutAnswer struct {
	Environment identity.EnvironmentID
	URL         string
	Fields      [][2]string
}

// LogoutProtocol reads and writes SAML logout messages (samlxml).
type LogoutProtocol interface {
	// DecodeLogout reads a LogoutRequest (not trusted yet).
	DecodeLogout(m LogoutMessage) (LogoutRequest, error)
	// VerifyLogout checks the message's signature with the provider's
	// certificate (query signature for HTTP-Redirect, XML signature for
	// HTTP-POST; unsigned is refused).
	VerifyLogout(m LogoutMessage, sp ServiceProvider) error
	// LogoutResponse signs the answer for the provider's slo_url and
	// binding.
	LogoutResponse(ctx context.Context, environment identity.EnvironmentID, sp ServiceProvider, request LogoutRequest, status string) (LogoutAnswer, error)
	// BackchannelLogout signs a LogoutRequest for the notification.
	BackchannelLogout(ctx context.Context, n LogoutNotification) ([]byte, error)
}

// LogoutSender posts a SOAP LogoutRequest to slo_soap_url (guarded
// transport) and checks the SOAP LogoutResponse's status.
type LogoutSender interface {
	Send(ctx context.Context, url string, envelope []byte) error
}

// LogoutRepository stores SLO state (samlpg).
type LogoutRepository interface {
	// RememberSession links a session to the provider its assertion went
	// to (idempotent).
	RememberSession(ctx context.Context, s IdPSession) error
	// EndSession ends the live session if it was asserted to the provider
	// for nameID, without queuing a back-channel notification for that
	// provider (iamkit.saml_logout_origin), and audits m; false when
	// nothing matched.
	EndSession(ctx context.Context, m Mutation, provider identity.ServiceProviderID, session identity.SessionID, nameID string) (bool, error)
	// ClaimLogouts leases up to limit due notifications.
	ClaimLogouts(ctx context.Context, limit int) ([]LogoutNotification, error)
	LogoutDelivered(ctx context.Context, id int64) error
	// LogoutRetry records a failed attempt (next attempt at next).
	LogoutRetry(ctx context.Context, id int64, next time.Time, problem string) error
	// LogoutFailed gives up and audits ActionLogoutFailed.
	LogoutFailed(ctx context.Context, n LogoutNotification, problem string) error
	PruneLogouts(ctx context.Context, before time.Time) error
}

// Logout status codes.
const (
	StatusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
)
