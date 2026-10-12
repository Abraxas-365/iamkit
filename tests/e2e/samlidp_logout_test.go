package e2e_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml/samltest"
	"github.com/gofiber/fiber/v2"
)

// TestSAMLIdPSingleLogout covers single logout with IAMKit as the identity
// provider: an application that registered slo_url, slo_soap_url and its
// certificate (opt-in) ends the user's session with a signed LogoutRequest
// (the answer is a signed LogoutResponse; unsigned, wrongly signed and
// foreign requests are refused and unknown sessions answer Requester), and
// when the session ends another way (admin revoke) IAMKit delivers a
// signed SOAP LogoutRequest to the application's back channel, retrying
// failures. The application that asked is not notified.
func TestSAMLIdPSingleLogout(t *testing.T) {
	sp := samltest.New("https://wiki.example.com/saml", "https://wiki.example.com/saml/acs")
	soap := sp.Backchannel()
	defer soap.Close()
	e := newEnv(t, bootstrap.WithSAMLLogoutTransport(soap.Client().Transport))
	base := e.Base + "/saml/service-providers"
	sloURL := "https://wiki.example.com/slo"

	// Validation: URLs need HTTPS and a certificate.
	create := fiber.Map{"name": "Wiki", "application_id": e.Client, "resource_id": e.Res, "entity_id": "https://wiki.example.com/saml", "acs_urls": []string{"https://wiki.example.com/saml/acs"}}
	with := func(extra fiber.Map) fiber.Map {
		out := fiber.Map{}
		for k, v := range create {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	e.Must("POST", base, e.Owner, with(fiber.Map{"slo_url": sloURL}), 400)
	e.Must("POST", base, e.Owner, with(fiber.Map{"slo_url": "http://wiki.example.com/slo", "certificate": sp.Certificate()}), 400)
	e.Must("POST", base, e.Owner, with(fiber.Map{"slo_url": sloURL, "certificate": "not a certificate"}), 400)
	e.Must("POST", base, e.Owner, with(fiber.Map{"slo_url": sloURL, "slo_binding": "soap", "certificate": sp.Certificate()}), 400)
	created := e.Must("POST", base, e.Owner, with(fiber.Map{"slo_url": sloURL, "slo_binding": "post", "slo_soap_url": soap.URL, "certificate": sp.Certificate(), "attributes": fiber.Map{"mail": "email"}}), 201).JSON
	id := created["id"].(string)
	if created["slo_url"] != sloURL || created["slo_binding"] != "post" || created["slo_soap_url"] != soap.URL || created["certificate"] != strings.TrimSpace(sp.Certificate()) {
		t.Fatalf("created = %v", created)
	}
	e.Must("PATCH", base+"/"+id, e.Owner, fiber.Map{"certificate": ""}, 400)
	e.Must("PATCH", base+"/"+id, e.Owner, fiber.Map{"slo_binding": "redirect"}, 200)

	b := e.browser()
	idp := e.Must("GET", e.Base+"/saml/identity-provider", e.Owner, nil, 200).JSON
	if idp["slo_url"] != "https://iam.example/saml/"+e.EnvID+"/slo" {
		t.Fatalf("identity provider = %v", idp)
	}
	metadata := b.get(ssoPath(t, idp["entity_id"].(string)))
	if err := sp.Trust([]byte(metadata.Body)); err != nil {
		t.Fatal(err)
	}

	signIn := func() string {
		t.Helper()
		redirect, requestID, err := sp.Redirect("")
		if err != nil {
			t.Fatal(err)
		}
		browser := e.browser()
		start := browser.get(ssoPath(t, redirect))
		login := browser.get(start.Location)
		tk := login.field("ticket")
		browser.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
		done := browser.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
		result, err := sp.Verify(postField(done, "SAMLResponse"), requestID)
		if err != nil {
			t.Fatalf("SP refused the response: %v\n%s", err, done.Body)
		}
		return result.SessionIndex
	}
	live := func(session string) bool {
		var n int
		e.DB.Get(&n, `SELECT count(*) FROM sessions WHERE id=$1 AND revoked_at IS NULL`, session)
		return n == 1
	}
	deliver := func() {
		t.Helper()
		found, err := e.Server.Workers.RunOnce(context.Background(), "saml_logout_delivery")
		if !found || err != nil {
			t.Fatalf("delivery job: found=%v err=%v", found, err)
		}
	}
	slo := ssoPath(t, idp["slo_url"].(string))

	// SP-initiated logout (HTTP-Redirect): refused unless signed by the
	// registered certificate.
	first := signIn()
	var links int
	e.DB.Get(&links, `SELECT count(*) FROM saml_idp_sessions WHERE session_id=$1 AND service_provider_id=$2 AND name_id=$3`, first, id, e.AliceEmail)
	if links != 1 {
		t.Fatalf("session links = %d", links)
	}
	unsigned, _, _ := sp.LogoutRedirect(samltest.LogoutOptions{NameID: e.AliceEmail, SessionIndex: first, Unsigned: true})
	if p := b.get(ssoPath(t, unsigned)); p.Status != 401 || !live(first) {
		t.Fatalf("unsigned request: %d live=%v", p.Status, live(first))
	}
	impostor, _, _ := sp.Impostor().LogoutRedirect(samltest.LogoutOptions{NameID: e.AliceEmail, SessionIndex: first})
	if p := b.get(ssoPath(t, impostor)); p.Status != 401 || !live(first) {
		t.Fatalf("badly signed request: %d live=%v", p.Status, live(first))
	}
	stranger := samltest.New("https://unknown.example.com/saml", "https://unknown.example.com/acs")
	if err := stranger.Trust([]byte(metadata.Body)); err != nil {
		t.Fatal(err)
	}
	foreign, _, _ := stranger.LogoutRedirect(samltest.LogoutOptions{NameID: e.AliceEmail, SessionIndex: first})
	if p := b.get(ssoPath(t, foreign)); p.Status != 401 || !live(first) {
		t.Fatalf("unregistered issuer: %d live=%v", p.Status, live(first))
	}
	if p := b.get(slo); p.Status != 400 {
		t.Fatalf("no request: %d", p.Status)
	}
	if p := b.get("/saml/" + e.Org + "/slo?SAMLRequest=x"); p.Status != 404 {
		t.Fatalf("unknown environment: %d", p.Status)
	}
	// Another NameID names no session of the application: Requester, and
	// the session stays.
	wrongName, requestID, _ := sp.LogoutRedirect(samltest.LogoutOptions{NameID: "eve@example.com", SessionIndex: first})
	p := b.get(ssoPath(t, wrongName))
	answer, err := sp.VerifyLogoutRedirect(p.Location)
	if p.Status != 303 || err != nil || answer.InResponseTo != requestID || answer.Status != "urn:oasis:names:tc:SAML:2.0:status:Requester" || !live(first) {
		t.Fatalf("unknown principal: %d %v %+v live=%v", p.Status, err, answer, live(first))
	}

	signed, requestID, err := sp.LogoutRedirect(samltest.LogoutOptions{NameID: e.AliceEmail, SessionIndex: first, RelayState: "back"})
	if err != nil {
		t.Fatal(err)
	}
	p = b.get(ssoPath(t, signed))
	answer, err = sp.VerifyLogoutRedirect(p.Location)
	if p.Status != 303 || err != nil || answer.InResponseTo != requestID || answer.Status != "urn:oasis:names:tc:SAML:2.0:status:Success" || answer.RelayState != "back" || answer.Destination != sloURL {
		t.Fatalf("logout: %d %v %+v", p.Status, err, answer)
	}
	if live(first) {
		t.Fatal("the session survived the logout")
	}
	var reason, actor string
	e.DB.Get(&reason, `SELECT data->>'reason' FROM events WHERE type='session.revoked' AND subject_id=$1`, first)
	e.DB.Get(&actor, `SELECT actor_id FROM events WHERE type='session.revoked' AND subject_id=$1`, first)
	if reason != "saml_logout" || actor != e.Alice {
		t.Fatalf("session.revoked reason=%q actor=%q", reason, actor)
	}
	var audits int
	e.DB.Get(&audits, `SELECT count(*) FROM events WHERE type='saml.logout' AND subject_id=$1`, id)
	if audits != 1 {
		t.Fatalf("saml.logout events = %d", audits)
	}
	// Replaying it: the session is gone, the answer reveals nothing more.
	p = b.get(ssoPath(t, signed))
	if answer, err = sp.VerifyLogoutRedirect(p.Location); err != nil || answer.Status != "urn:oasis:names:tc:SAML:2.0:status:Requester" {
		t.Fatalf("replay: %d %v %+v", p.Status, err, answer)
	}
	// The application that asked is not told again.
	deliver()
	if got := soap.Received(); len(got) != 0 {
		t.Fatalf("origin notified: %+v", got)
	}
	var queued int
	e.DB.Get(&queued, `SELECT count(*) FROM saml_logout_notifications WHERE session_id=$1`, first)
	if queued != 0 {
		t.Fatalf("notifications queued for the origin: %d", queued)
	}

	// HTTP-POST binding answers with a signed form.
	e.Must("PATCH", base+"/"+id, e.Owner, fiber.Map{"slo_binding": "post"}, 200)
	second := signIn()
	post, requestID, err := sp.LogoutPost(samltest.LogoutOptions{NameID: e.AliceEmail, SessionIndex: second, RelayState: "r2"})
	if err != nil {
		t.Fatal(err)
	}
	done := b.post(slo, url.Values{"SAMLRequest": {post}, "RelayState": {"r2"}})
	if done.Status != 200 {
		t.Fatalf("post logout: %d %s", done.Status, done.Body)
	}
	answer, err = sp.VerifyLogoutPost(postField(done, "SAMLResponse"))
	if err != nil || answer.InResponseTo != requestID || answer.Status != "urn:oasis:names:tc:SAML:2.0:status:Success" || postField(done, "RelayState") != "r2" || live(second) {
		t.Fatalf("post logout: %v %+v live=%v", err, answer, live(second))
	}
	unsignedPost, _, _ := sp.LogoutPost(samltest.LogoutOptions{NameID: e.AliceEmail, SessionIndex: second, Unsigned: true})
	if p := b.post(slo, url.Values{"SAMLRequest": {unsignedPost}}); p.Status != 401 {
		t.Fatalf("unsigned POST request: %d", p.Status)
	}

	// An operator ends the session: the application gets a signed SOAP
	// LogoutRequest; failures are retried.
	third := signIn()
	soap.FailNext(1)
	e.Must("POST", e.Base+"/users/"+e.Alice+"/revoke-sessions", e.Owner, nil, 200)
	if live(third) {
		t.Fatal("the session survived the revoke")
	}
	deliver()
	if got := soap.Received(); len(got) != 0 {
		t.Fatalf("delivered despite the failure: %+v", got)
	}
	var attempts int
	var problem string
	e.DB.Get(&attempts, `SELECT attempts FROM saml_logout_notifications WHERE session_id=$1`, third)
	e.DB.Get(&problem, `SELECT last_error FROM saml_logout_notifications WHERE session_id=$1`, third)
	if attempts != 1 || problem == "" {
		t.Fatalf("attempts=%d error=%q", attempts, problem)
	}
	e.DB.MustExec(`UPDATE saml_logout_notifications SET next_attempt_at = now() WHERE session_id=$1`, third)
	deliver()
	got := soap.Received()
	if len(got) != 1 || got[0].SessionIndex != third || got[0].NameID != e.AliceEmail || got[0].Destination != soap.URL {
		t.Fatalf("received = %+v", got)
	}
	var delivered int
	e.DB.Get(&delivered, `SELECT count(*) FROM saml_logout_notifications WHERE session_id=$1 AND delivered_at IS NOT NULL`, third)
	if delivered != 1 {
		t.Fatalf("delivered rows = %d", delivered)
	}
	deliver()
	if len(soap.Received()) != 1 {
		t.Fatal("delivered twice")
	}

	// Giving up is audited.
	fourth := signIn()
	soap.FailNext(100)
	e.Must("POST", e.Base+"/users/"+e.Alice+"/revoke-sessions", e.Owner, nil, 200)
	e.DB.MustExec(`UPDATE saml_logout_notifications SET attempts = 7 WHERE session_id=$1`, fourth)
	deliver()
	var failed int
	e.DB.Get(&failed, `SELECT count(*) FROM events WHERE type='saml.logout_failed' AND subject_id=$1 AND actor_kind='system'`, id)
	if failed != 1 {
		t.Fatalf("saml.logout_failed events = %d", failed)
	}
}
