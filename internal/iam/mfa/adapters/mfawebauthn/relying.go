// Package mfawebauthn is the WebAuthn relying party of security keys and
// passkeys. It is the only importer of go-webauthn.
package mfawebauthn

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// RelyingParty verifies ceremonies for one relying party id (the issuer's
// host) and its origins. The zero value is disabled.
type RelyingParty struct {
	web *webauthn.WebAuthn
}

var _ mfa.Relying = RelyingParty{}

// New builds the relying party of an issuer URL: its host is the relying
// party id and its origin the accepted origin, plus extra origins (custom
// sign-in UIs on subdomains). An issuer whose host cannot be a relying
// party id (an IP address) disables WebAuthn.
func New(issuer string, origins []string) RelyingParty {
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" {
		return RelyingParty{}
	}
	all := []string{u.Scheme + "://" + u.Host}
	for _, o := range origins {
		if o = strings.TrimSuffix(strings.TrimSpace(o), "/"); o != "" {
			all = append(all, o)
		}
	}
	web, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "IAMKit",
		RPOrigins:     all,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: config.WebAuthnCeremonyTTL, TimeoutUVD: config.WebAuthnCeremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: config.WebAuthnCeremonyTTL, TimeoutUVD: config.WebAuthnCeremonyTTL},
		},
	})
	if err != nil {
		return RelyingParty{}
	}
	return RelyingParty{web: web}
}

func (r RelyingParty) Enabled() bool { return r.web != nil }

func (r RelyingParty) Register(holder mfa.Holder, passkey bool) (mfa.Challenge, error) {
	if r.web == nil {
		return mfa.Challenge{}, mfa.ErrWebAuthnUnavailable()
	}
	selection := protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementDiscouraged, UserVerification: protocol.VerificationDiscouraged}
	if passkey {
		selection = protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(), UserVerification: protocol.VerificationRequired}
	}
	u := user{holder}
	exclude := make([]protocol.CredentialDescriptor, 0, len(holder.Credentials))
	for _, c := range u.WebAuthnCredentials() {
		exclude = append(exclude, c.Descriptor())
	}
	opts := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(selection),
		webauthn.WithExclusions(exclude),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	}
	if holder.RelyingParty != "" {
		opts = append(opts, webauthn.WithRegistrationRelyingPartyName(holder.RelyingParty))
	}
	creation, session, err := r.web.BeginRegistration(u, opts...)
	if err != nil {
		return mfa.Challenge{}, errx.Wrap(err, "start security key registration", errx.TypeInternal)
	}
	return challenge(creation.Response, session)
}

func (r RelyingParty) Created(holder mfa.Holder, state, response []byte) (mfa.Credential, error) {
	if r.web == nil {
		return mfa.Credential{}, mfa.ErrWebAuthnUnavailable()
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return mfa.Credential{}, errx.Wrap(err, "read security key ceremony", errx.TypeInternal)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return mfa.Credential{}, rejected()
	}
	c, err := r.web.CreateCredential(user{holder}, session, parsed)
	if err != nil {
		return mfa.Credential{}, rejected()
	}
	return credential(*c), nil
}

func (r RelyingParty) Assert(holder mfa.Holder, verifyUser bool) (mfa.Challenge, error) {
	if r.web == nil {
		return mfa.Challenge{}, mfa.ErrWebAuthnUnavailable()
	}
	uv := protocol.VerificationDiscouraged
	if verifyUser {
		uv = protocol.VerificationRequired
	}
	var (
		assertion *protocol.CredentialAssertion
		session   *webauthn.SessionData
		err       error
	)
	if len(holder.Handle) == 0 {
		assertion, session, err = r.web.BeginDiscoverableLogin(webauthn.WithUserVerification(uv))
	} else {
		if len(holder.Credentials) == 0 {
			return mfa.Challenge{}, errx.NotFound("no security key is enrolled")
		}
		assertion, session, err = r.web.BeginLogin(user{holder}, webauthn.WithUserVerification(uv))
	}
	if err != nil {
		return mfa.Challenge{}, errx.Wrap(err, "start security key sign-in", errx.TypeInternal)
	}
	return challenge(assertion.Response, session)
}

func (r RelyingParty) Handle(response []byte) ([]byte, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil || len(parsed.Response.UserHandle) == 0 {
		return nil, rejected()
	}
	return parsed.Response.UserHandle, nil
}

func (r RelyingParty) Asserted(holder mfa.Holder, state, response []byte) (mfa.Assertion, error) {
	if r.web == nil {
		return mfa.Assertion{}, mfa.ErrWebAuthnUnavailable()
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return mfa.Assertion{}, errx.Wrap(err, "read security key ceremony", errx.TypeInternal)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return mfa.Assertion{}, rejected()
	}
	u := user{holder}
	var c *webauthn.Credential
	if len(session.UserID) == 0 {
		c, err = r.web.ValidateDiscoverableLogin(func(_, handle []byte) (webauthn.User, error) {
			if !bytes.Equal(handle, holder.Handle) {
				return nil, rejected()
			}
			return u, nil
		}, session, parsed)
	} else {
		c, err = r.web.ValidateLogin(u, session, parsed)
	}
	if err != nil {
		return mfa.Assertion{}, rejected()
	}
	return mfa.Assertion{Credential: credential(*c), Handle: parsed.Response.UserHandle, Clone: c.Authenticator.CloneWarning}, nil
}

func challenge(options any, session *webauthn.SessionData) (mfa.Challenge, error) {
	opts, err := json.Marshal(options)
	if err != nil {
		return mfa.Challenge{}, errx.Wrap(err, "encode security key options", errx.TypeInternal)
	}
	state, err := json.Marshal(session)
	if err != nil {
		return mfa.Challenge{}, errx.Wrap(err, "encode security key ceremony", errx.TypeInternal)
	}
	return mfa.Challenge{Options: opts, State: state}, nil
}

// rejected answers every invalid attestation or assertion alike.
func rejected() error { return errx.Unauthorized("the security key could not be verified") }

func credential(c webauthn.Credential) mfa.Credential {
	out := mfa.Credential{
		ID: c.ID, PublicKey: c.PublicKey, AttestationType: c.AttestationType, AttestationFormat: c.AttestationFormat,
		AAGUID: c.Authenticator.AAGUID, SignCount: c.Authenticator.SignCount,
		UserPresent: c.Flags.UserPresent, UserVerified: c.Flags.UserVerified,
		BackupEligible: c.Flags.BackupEligible, BackupState: c.Flags.BackupState,
	}
	for _, t := range c.Transport {
		out.Transports = append(out.Transports, string(t))
	}
	return out
}

// user adapts a holder to go-webauthn.
type user struct{ h mfa.Holder }

func (u user) WebAuthnID() []byte          { return u.h.Handle }
func (u user) WebAuthnName() string        { return u.h.Name }
func (u user) WebAuthnDisplayName() string { return u.h.DisplayName }
func (u user) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.h.Credentials))
	for _, c := range u.h.Credentials {
		wc := webauthn.Credential{
			ID: c.ID, PublicKey: c.PublicKey, AttestationType: c.AttestationType, AttestationFormat: c.AttestationFormat,
			Flags:         webauthn.CredentialFlags{UserPresent: c.UserPresent, UserVerified: c.UserVerified, BackupEligible: c.BackupEligible, BackupState: c.BackupState},
			Authenticator: webauthn.Authenticator{AAGUID: c.AAGUID, SignCount: c.SignCount},
		}
		for _, t := range c.Transports {
			wc.Transport = append(wc.Transport, protocol.AuthenticatorTransport(t))
		}
		out = append(out, wc)
	}
	return out
}
