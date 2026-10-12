package samlxml_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml/samltest"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func sloSetup(t *testing.T, binding string) (samlxml.Protocol, identity.EnvironmentID, *samltest.SP, samlidp.ServiceProvider) {
	t.Helper()
	protocol, environment, sp, registered := setup(t)
	// The trusted metadata lists the SLO endpoints.
	metadata, err := protocol.Metadata(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Trust(metadata); err != nil {
		t.Fatal(err)
	}
	registered.Certificate = sp.Certificate()
	registered.SLOURL = "https://wiki.example.com/slo"
	registered.SLOBinding = binding
	return protocol, environment, sp, registered
}

func redirectMessage(t *testing.T, raw string) samlidp.LogoutMessage {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return samlidp.LogoutMessage{Redirect: true, SAMLRequest: u.Query().Get("SAMLRequest"), RelayState: u.Query().Get("RelayState"), RawQuery: u.RawQuery}
}

func TestLogoutRedirectVerified(t *testing.T) {
	protocol, _, sp, registered := sloSetup(t, samlidp.SLOBindingRedirect)
	raw, id, err := sp.LogoutRedirect(samltest.LogoutOptions{NameID: "ada@example.com", SessionIndex: "sess-1", RelayState: "r 1&x"})
	if err != nil {
		t.Fatal(err)
	}
	m := redirectMessage(t, raw)
	request, err := protocol.DecodeLogout(m)
	if err != nil {
		t.Fatal(err)
	}
	if request.ID != id || request.Issuer != registered.EntityID || request.NameID != "ada@example.com" || len(request.SessionIndexes) != 1 || request.SessionIndexes[0] != "sess-1" || request.RelayState != "r 1&x" {
		t.Fatalf("request: %+v", request)
	}
	if err := protocol.VerifyLogout(m, registered); err != nil {
		t.Fatalf("signed request refused: %v", err)
	}
}

func TestLogoutRedirectRefused(t *testing.T) {
	protocol, _, sp, registered := sloSetup(t, samlidp.SLOBindingRedirect)
	other := sp.Impostor()
	cases := map[string]func() string{
		"unsigned": func() string {
			raw, _, _ := sp.LogoutRedirect(samltest.LogoutOptions{NameID: "a@b.c", Unsigned: true})
			return raw
		},
		"wrong key": func() string {
			raw, _, _ := other.LogoutRedirect(samltest.LogoutOptions{NameID: "a@b.c"})
			return raw
		},
		"sha1": func() string {
			raw, _, _ := sp.LogoutRedirect(samltest.LogoutOptions{NameID: "a@b.c", SHA1: true})
			return raw
		},
		"tampered relay state": func() string {
			raw, _, _ := sp.LogoutRedirect(samltest.LogoutOptions{NameID: "a@b.c", RelayState: "x"})
			return strings.Replace(raw, "RelayState=x", "RelayState=y", 1)
		},
		"tampered request": func() string {
			raw, _, _ := sp.LogoutRedirect(samltest.LogoutOptions{NameID: "a@b.c"})
			return strings.Replace(raw, "SAMLRequest=", "SAMLRequest=A", 1)
		},
	}
	// The impostor has its own key; the registered certificate is the SP's.
	for name, build := range cases {
		m := redirectMessage(t, build())
		if name == "tampered request" {
			if _, err := protocol.DecodeLogout(m); err != nil {
				continue // refused even earlier
			}
		}
		if err := protocol.VerifyLogout(m, registered); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The registered certificate of another application refuses it too.
	raw, _, _ := sp.LogoutRedirect(samltest.LogoutOptions{NameID: "a@b.c"})
	wrong := registered
	wrong.Certificate = other.Certificate()
	if err := protocol.VerifyLogout(redirectMessage(t, raw), wrong); err == nil {
		t.Error("request verified against another certificate")
	}
	none := registered
	none.Certificate = ""
	if err := protocol.VerifyLogout(redirectMessage(t, raw), none); err == nil {
		t.Error("request verified without a registered certificate")
	}
}

func TestLogoutPost(t *testing.T) {
	protocol, _, sp, registered := sloSetup(t, samlidp.SLOBindingPOST)
	raw, id, err := sp.LogoutPost(samltest.LogoutOptions{NameID: "ada@example.com", SessionIndex: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	m := samlidp.LogoutMessage{SAMLRequest: raw, RelayState: "r"}
	request, err := protocol.DecodeLogout(m)
	if err != nil || request.ID != id || request.NameID != "ada@example.com" {
		t.Fatalf("decode: %+v %v", request, err)
	}
	if err := protocol.VerifyLogout(m, registered); err != nil {
		t.Fatalf("signed request refused: %v", err)
	}
	refuse := map[string]samltest.LogoutOptions{
		"unsigned": {NameID: "a@b.c", Unsigned: true},
		"sha1":     {NameID: "a@b.c", SHA1: true},
	}
	for name, o := range refuse {
		raw, _, err := sp.LogoutPost(o)
		if err != nil {
			t.Fatal(err)
		}
		if err := protocol.VerifyLogout(samlidp.LogoutMessage{SAMLRequest: raw}, registered); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	raw, _, _ = sp.Impostor().LogoutPost(samltest.LogoutOptions{NameID: "a@b.c"})
	if err := protocol.VerifyLogout(samlidp.LogoutMessage{SAMLRequest: raw}, registered); err == nil {
		t.Error("request signed with another key accepted")
	}
	raw, _, _ = sp.LogoutPost(samltest.LogoutOptions{NameID: "a@b.c"})
	other := samltest.New("https://other.example.com/saml", "https://other.example.com/acs")
	wrong := registered
	wrong.Certificate = other.Certificate()
	if err := protocol.VerifyLogout(samlidp.LogoutMessage{SAMLRequest: raw}, wrong); err == nil {
		t.Error("request verified against another certificate")
	}
}

func TestLogoutDecodeRejects(t *testing.T) {
	protocol, _, _, _ := sloSetup(t, samlidp.SLOBindingRedirect)
	for name, m := range map[string]samlidp.LogoutMessage{
		"empty":       {},
		"not base64":  {SAMLRequest: "!!!"},
		"not xml":     {SAMLRequest: "aGVsbG8="},
		"not deflate": {Redirect: true, SAMLRequest: "aGVsbG8="},
		"too large":   {SAMLRequest: strings.Repeat("A", samlidp.MaxLogoutMessage+1)},
	} {
		if _, err := protocol.DecodeLogout(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLogoutResponseSigned(t *testing.T) {
	ctx := context.Background()
	for _, binding := range []string{samlidp.SLOBindingRedirect, samlidp.SLOBindingPOST} {
		protocol, environment, sp, registered := sloSetup(t, binding)
		request := samlidp.LogoutRequest{ID: "req-1", Issuer: registered.EntityID, RelayState: "relay"}
		answer, err := protocol.LogoutResponse(ctx, environment, registered, request, samlidp.StatusSuccess)
		if err != nil {
			t.Fatal(err)
		}
		var got samltest.LogoutResponse
		if binding == samlidp.SLOBindingRedirect {
			if len(answer.Fields) != 0 || !strings.HasPrefix(answer.URL, registered.SLOURL+"?SAMLResponse=") {
				t.Fatalf("%s answer: %+v", binding, answer)
			}
			got, err = sp.VerifyLogoutRedirect(answer.URL)
		} else {
			if answer.URL != registered.SLOURL || len(answer.Fields) != 2 || answer.Fields[0][0] != "SAMLResponse" || answer.Fields[1] != [2]string{"RelayState", "relay"} {
				t.Fatalf("%s answer: %+v", binding, answer)
			}
			got, err = sp.VerifyLogoutPost(answer.Fields[0][1])
		}
		if err != nil {
			t.Fatalf("%s: response refused: %v", binding, err)
		}
		if got.InResponseTo != "req-1" || got.Status != samlidp.StatusSuccess || got.Destination != registered.SLOURL {
			t.Fatalf("%s: %+v", binding, got)
		}
	}
}

func TestBackchannelLogout(t *testing.T) {
	protocol, environment, sp, registered := sloSetup(t, samlidp.SLOBindingRedirect)
	endpoint := sp.Backchannel()
	defer endpoint.Close()
	registered.SLOSOAPURL = endpoint.URL
	session := identity.NewSessionID()
	n := samlidp.LogoutNotification{ID: 1, Environment: environment, ServiceProvider: registered, Session: session, NameID: "ada@example.com"}
	envelope, err := protocol.BackchannelLogout(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if err := samlxml.NewSender(nil).Send(context.Background(), endpoint.URL, envelope); err == nil {
		t.Fatal("the guarded transport reached a loopback address")
	}
	sender := samlxml.NewSender(endpoint.Client().Transport)
	if err := sender.Send(context.Background(), endpoint.URL, envelope); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := endpoint.Received()
	if len(got) != 1 || got[0].NameID != "ada@example.com" || got[0].SessionIndex != session.String() || got[0].Destination != endpoint.URL {
		t.Fatalf("received: %+v", got)
	}
	// Errors are surfaced for retries.
	endpoint.FailNext(1)
	if err := sender.Send(context.Background(), endpoint.URL, envelope); err == nil {
		t.Fatal("HTTP 500 counted as delivered")
	}
	endpoint.Status = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	if err := sender.Send(context.Background(), endpoint.URL, envelope); err == nil {
		t.Fatal("a Responder status counted as delivered")
	}
	endpoint.Status = ""
	// A request whose signature the application cannot verify is refused by it.
	tampered := []byte(strings.Replace(string(envelope), "ada@example.com", "eve@example.com", 1))
	if err := sender.Send(context.Background(), endpoint.URL, tampered); err == nil {
		t.Fatal("tampered request accepted by the application")
	}
}

func TestMetadataListsSingleLogout(t *testing.T) {
	protocol, environment, _, _ := setup(t)
	metadata, err := protocol.Metadata(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	slo := "https://iam.example.com/saml/" + environment.String() + "/slo"
	for _, binding := range []string{"HTTP-Redirect", "HTTP-POST"} {
		if !strings.Contains(string(metadata), `Binding="urn:oasis:names:tc:SAML:2.0:bindings:`+binding+`" Location="`+slo+`"`) {
			t.Errorf("metadata lacks a %s SingleLogoutService:\n%s", binding, metadata)
		}
	}
}
