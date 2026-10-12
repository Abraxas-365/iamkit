package e2e_test

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml/samltest"
	"github.com/crewjam/saml"
	"github.com/gofiber/fiber/v2"
)

// TestSAMLSingleLogout covers SAML single logout with IAMKit as the service
// provider: an IdP-initiated LogoutRequest ends the linked sessions (and a
// replay or a forged one does nothing), and /oauth/end_session continues at
// the IdP whose LogoutResponse brings the browser back to the registered
// post_logout_redirect_uri.
func TestSAMLSingleLogout(t *testing.T) {
	for _, binding := range []string{"redirect", "post"} {
		t.Run(binding, func(t *testing.T) { samlSingleLogout(t, binding) })
	}
}

func samlSingleLogout(t *testing.T, binding string) {
	e := newEnv(t)
	post := binding == "post"
	idp := samltest.New("https://idp.example.com")
	idp.SLO = binding
	connections := e.Base + "/federation-connections"
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	app := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback"}, "post_logout_redirect_uris": []string{"https://app.example/bye"}, "public": true, "hosted_login": true}, 201).JSON["client_id"].(string)

	// The option needs a SingleLogoutService in the IdP's metadata.
	plain := samltest.New("https://plain.example.com")
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Plain", "provider": "saml", "options": fiber.Map{"metadata_xml": plain.Metadata(), "single_logout": true}}, 400)

	conn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "saml", "options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent", "single_logout": true}})
	sp := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON["saml"].(map[string]any)
	metadata := e.follow(strings.TrimPrefix(sp["metadata_url"].(string), "https://iam.example"), nil)
	if !strings.Contains(metadata.Body, "SingleLogoutService") {
		t.Fatalf("SP metadata without a SingleLogoutService: %s", metadata.Body)
	}
	if err := idp.Trust([]byte(metadata.Body)); err != nil {
		t.Fatal(err)
	}
	entity := sp["entity_id"].(string)
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Everyone"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"jit_group_id": group}, 204)
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)

	user := samltest.User{NameID: "00u-dave", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "dave@example.com", Name: "Dave", SessionIndex: "idp-session-1"}
	live := func() int {
		var n int
		if err := e.DB.Get(&n, `SELECT count(*) FROM sessions s JOIN federation_sessions f ON f.session_id = s.id WHERE s.revoked_at IS NULL AND f.connection_id = $1`, conn); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// signIn runs a hosted SAML login and returns its tokens.
	signIn := func() (*browser, map[string]any) {
		t.Helper()
		b := e.browser()
		start := b.authorizeWith(app, url.Values{"connection_id": {conn}, "organization_id": {e.Org}})
		hop := b.get(start.Location)
		if hop.Status != 303 || !strings.HasPrefix(hop.Location, "https://idp.example.com/sso?SAMLRequest=") {
			t.Fatalf("hosted login: %d %q %s", hop.Status, hop.Location, hop.Body)
		}
		answer, err := idp.Answer(hop.Location, user)
		if err != nil {
			t.Fatal(err)
		}
		parked := b.post("/identity/v1/federation/saml/acs", url.Values{"SAMLResponse": {answer.SAMLResponse}, "RelayState": {answer.RelayState}})
		if parked.Status != 303 {
			t.Fatalf("acs: %d %s", parked.Status, parked.Body)
		}
		return b, b.exchange(app, b.get(parked.Location))
	}
	// deliver hands an IdP message to IAMKit's SLO endpoint.
	deliver := func(b *browser, m samltest.Message) page {
		t.Helper()
		if m.Post() {
			form := url.Values{}
			for _, f := range m.Fields {
				form.Set(f[0], f[1])
			}
			return b.post(strings.TrimPrefix(m.URL, "https://iam.example"), form)
		}
		return b.get(strings.TrimPrefix(m.URL, "https://iam.example"))
	}
	// reply reads the answer IAMKit sent back to the IdP.
	reply := func(p page) samltest.Message {
		t.Helper()
		if post {
			if p.Status != 200 || !strings.Contains(p.Body, "https://idp.example.com/slo") || samlField(p, "SAMLResponse") == "" {
				t.Fatalf("expected an auto-post to the IdP: %d %s", p.Status, p.Body)
			}
			return samltest.Message{URL: "https://idp.example.com/slo"}
		}
		if p.Status != 303 || !strings.HasPrefix(p.Location, "https://idp.example.com/slo?") || !strings.Contains(p.Location, "SAMLResponse=") {
			t.Fatalf("expected a redirect to the IdP: %d %q %s", p.Status, p.Location, p.Body)
		}
		return samltest.Message{URL: p.Location}
	}

	// IdP-initiated: the LogoutRequest ends the session; the answer is signed.
	b, _ := signIn()
	if n := live(); n != 1 {
		t.Fatalf("federation sessions after sign-in = %d", n)
	}
	request, err := idp.LogoutRequest(entity, user, post, "relay-1")
	if err != nil {
		t.Fatal(err)
	}
	reply(deliver(b, request))
	if n := live(); n != 0 {
		t.Fatalf("sessions alive after the IdP's LogoutRequest = %d", n)
	}
	var events int
	if err = e.DB.Get(&events, `SELECT count(*) FROM events WHERE type = 'connection.single_logout'`); err != nil || events != 1 {
		t.Fatalf("connection.single_logout events = %d %v", events, err)
	}
	// A replay ends nothing more and gets no answer.
	if again := deliver(b, request); again.Status != 401 {
		t.Fatalf("replayed LogoutRequest: %d %s", again.Status, again.Body)
	}
	// A request signed by another key, or for another NameID, ends nothing.
	b, _ = signIn()
	forger := samltest.New("https://idp.example.com")
	_ = forger.Trust([]byte(metadata.Body))
	forger.SLO = binding
	forged, err := forger.LogoutRequest(entity, user, post, "")
	if err != nil {
		t.Fatal(err)
	}
	if res := deliver(b, forged); res.Status != 401 {
		t.Fatalf("forged LogoutRequest: %d %s", res.Status, res.Body)
	}
	unsigned, err := idp.LogoutRequest(entity, user, post, "", samltest.Tamper{Unsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if res := deliver(b, unsigned); res.Status != 401 {
		t.Fatalf("unsigned LogoutRequest: %d %s", res.Status, res.Body)
	}
	stranger := user
	stranger.NameID = "00u-someone-else"
	other, err := idp.LogoutRequest(entity, stranger, post, "")
	if err != nil {
		t.Fatal(err)
	}
	reply(deliver(b, other))
	if n := live(); n != 1 {
		t.Fatalf("sessions after refused or unrelated requests = %d, want 1", n)
	}

	// SP-initiated: end_session ends the session, then continues at the IdP.
	_, tokens := signIn()
	end := e.browser().get("/oauth/end_session?" + url.Values{"id_token_hint": {tokens["id_token"].(string)}, "post_logout_redirect_uri": {"https://app.example/bye"}, "state": {"s1"}}.Encode())
	var sent samltest.Message
	if post {
		if end.Status != 200 || !strings.Contains(end.Body, "https://idp.example.com/slo") || samlField(end, "SAMLRequest") == "" {
			t.Fatalf("end_session: %d %s", end.Status, end.Body)
		}
		sent = samltest.Message{URL: "https://idp.example.com/slo", Fields: [][2]string{{"SAMLRequest", samlField(end, "SAMLRequest")}, {"RelayState", samlField(end, "RelayState")}}}
	} else {
		if end.Status != 303 || !strings.HasPrefix(end.Location, "https://idp.example.com/slo?SAMLRequest=") {
			t.Fatalf("end_session: %d %q %s", end.Status, end.Location, end.Body)
		}
		sent = samltest.Message{URL: end.Location}
	}
	if n := live(); n != 1 {
		t.Fatalf("sessions after end_session = %d, want only the one left from before", n)
	}
	logout, response, err := idp.AnswerLogout(entity, sent)
	if err != nil {
		t.Fatal(err)
	}
	if logout.NameID != user.NameID || logout.SessionIndex != user.SessionIndex {
		t.Fatalf("IdP read %+v", logout)
	}
	// The IdP's answer continues to the registered redirect, once.
	back := deliver(e.browser(), response)
	if back.Status != 303 || back.Location != "https://app.example/bye?state=s1" {
		t.Fatalf("LogoutResponse: %d %q %s", back.Status, back.Location, back.Body)
	}
	if replay := deliver(e.browser(), response); replay.Status < 400 {
		t.Fatalf("LogoutResponse accepted twice: %d %q", replay.Status, replay.Location)
	}
}

var samlFormField = regexp.MustCompile(`name="(\w+)" value="([^"]*)"`)

// samlField reads a hidden field of an auto-post page (SAML field names
// are mixed case, which page.field does not match).
func samlField(p page, name string) string {
	for _, m := range samlFormField.FindAllStringSubmatch(p.Body, -1) {
		if m[1] == name {
			return html.UnescapeString(m[2])
		}
	}
	return ""
}
