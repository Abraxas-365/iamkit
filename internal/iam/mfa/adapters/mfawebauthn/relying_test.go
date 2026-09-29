package mfawebauthn_test

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfawebauthn"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfawebauthn/softkey"
)

const origin = "https://iam.example"

var holder = mfa.Holder{Handle: []byte("22222222-2222-4222-8222-222222222222"), Name: "alice@example.com", DisplayName: "alice@example.com"}

func register(t *testing.T, r mfawebauthn.RelyingParty, passkey bool) (*softkey.Key, mfa.Credential) {
	t.Helper()
	ch, err := r.Register(holder, passkey)
	if err != nil {
		t.Fatal(err)
	}
	key, answer, err := softkey.Create(ch.Options, origin, passkey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Created(holder, ch.State, answer)
	if err != nil {
		t.Fatalf("created: %v", err)
	}
	return key, c
}

func TestSecurityKeyCeremonies(t *testing.T) {
	r := mfawebauthn.New(origin+"/", nil)
	if !r.Enabled() {
		t.Fatal("a host issuer enables WebAuthn")
	}
	key, c := register(t, r, false)
	if string(c.ID) != string(key.ID) || len(c.PublicKey) == 0 || c.UserVerified {
		t.Fatalf("credential %+v", c)
	}
	h := holder
	h.Credentials = []mfa.Credential{c}
	ch, err := r.Assert(h, false)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := key.Get(ch.Options, origin)
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Asserted(h, ch.State, answer)
	if err != nil || a.Clone || a.Credential.SignCount != 1 {
		t.Fatalf("asserted %+v %v", a, err)
	}

	// A foreign origin, a replayed state or a counter going back fail.
	ch, _ = r.Assert(h, false)
	answer, _ = key.Get(ch.Options, "https://evil.example")
	if _, err = r.Asserted(h, ch.State, answer); err == nil {
		t.Fatal("foreign origin accepted")
	}
	h.Credentials[0].SignCount = 10
	ch, _ = r.Assert(h, false)
	answer, _ = key.Get(ch.Options, origin)
	if a, err = r.Asserted(h, ch.State, answer); err != nil || !a.Clone {
		t.Fatalf("counter regression must flag a clone: %+v %v", a, err)
	}
}

func TestPasskeyCeremony(t *testing.T) {
	r := mfawebauthn.New(origin, nil)
	key, c := register(t, r, true)
	if !c.UserVerified {
		t.Fatal("passkey registration verifies the user")
	}
	ch, err := r.Assert(mfa.Holder{}, true)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := key.Get(ch.Options, origin)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := r.Handle(answer)
	if err != nil || string(handle) != string(holder.Handle) {
		t.Fatalf("handle %q %v", handle, err)
	}
	h := holder
	h.Credentials = []mfa.Credential{c}
	if a, err := r.Asserted(h, ch.State, answer); err != nil || !a.Credential.UserVerified {
		t.Fatalf("passkey asserted %+v %v", a, err)
	}
	other := h
	other.Handle = []byte("someone-else")
	ch, _ = r.Assert(mfa.Holder{}, true)
	answer, _ = key.Get(ch.Options, origin)
	if _, err = r.Asserted(other, ch.State, answer); err == nil {
		t.Fatal("assertion for another holder accepted")
	}
}

func TestDisabledRelyingParty(t *testing.T) {
	r := mfawebauthn.New("", nil)
	if r.Enabled() {
		t.Fatal("no issuer, no relying party")
	}
	if _, err := r.Register(holder, false); err == nil {
		t.Fatal("disabled relying party registered")
	}
}
