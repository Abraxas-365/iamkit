package e2e_test

import (
	"encoding/base64"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml/samltest"
	"github.com/crewjam/saml"
	"github.com/gofiber/fiber/v2"
)

// acsRaw posts a SAML response to the ACS and returns status, Location and
// body (acs only reports the redirect).
func (e *Env) acsRaw(response, relayState string) (int, string, string) {
	e.t.Helper()
	form := url.Values{"SAMLResponse": {response}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	req := httptest.NewRequest("POST", "/identity/v1/federation/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header.Get("Location"), string(raw)
}

// TestSAMLIdPInitiated covers IdP-initiated login the WorkOS way: the
// unsolicited response signs nobody in; IAMKit verifies it and redirects to
// the sign-in endpoint (initiate_login_uri) of the connection's OAuth client
// with connection_id, which then starts an ordinary SP-initiated login.
func TestSAMLIdPInitiated(t *testing.T) {
	e := newEnv(t)
	idp := samltest.New("https://idp.example.com")
	connections := e.Base + "/federation-connections"
	clients := e.Base + "/oauth-clients"
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))

	// initiate_login_uri: https (or loopback http) only, on create and update.
	create := func(extra fiber.Map) fiber.Map {
		body := fiber.Map{"application_id": e.Client, "resource_id": e.Res, "redirect_uris": []string{"https://app.example/callback", "https://app.example/other"}, "public": true, "hosted_login": true}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	for _, bad := range []string{"http://app.example/login", "/login", "https://u:p@app.example/login", "https://app.example/login#x"} {
		e.Must("POST", clients, e.Owner, create(fiber.Map{"initiate_login_uri": bad}), 400)
	}
	plain := e.Must("POST", clients, e.Owner, create(nil), 201).JSON
	plainID := plain["client_id"].(string)
	if v := e.Must("GET", clients+"/"+plain["id"].(string), e.Owner, nil, 200).JSON; v["initiate_login_uri"] != "" {
		t.Fatalf("default initiate_login_uri = %v", v["initiate_login_uri"])
	}
	e.Must("PATCH", clients+"/"+plain["id"].(string), e.Owner, fiber.Map{"initiate_login_uri": "http://app.example/login"}, 400)
	e.Must("PATCH", clients+"/"+plain["id"].(string), e.Owner, fiber.Map{"initiate_login_uri": "http://localhost:3000/login"}, 204)
	e.Must("PATCH", clients+"/"+plain["id"].(string), e.Owner, fiber.Map{"initiate_login_uri": ""}, 204)

	app := e.Must("POST", clients, e.Owner, create(fiber.Map{"initiate_login_uri": "https://app.example/login?tenant=acme"}), 201).JSON
	appID := app["client_id"].(string)
	if v := e.Must("GET", clients+"/"+app["id"].(string), e.Owner, nil, 200).JSON; v["initiate_login_uri"] != "https://app.example/login?tenant=acme" {
		t.Fatalf("created client = %v", v)
	}
	second := e.Must("POST", clients, e.Owner, create(fiber.Map{"initiate_login_uri": "https://second.example/sso", "redirect_uris": []string{"https://second.example/cb"}}), 201).JSON["client_id"].(string)

	// The connection, without an IdP-initiated client: refused with a clear 400.
	conn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "saml", "options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent"}})
	detail := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON
	sp := detail["saml"].(map[string]any)
	metadata := e.follow(strings.TrimPrefix(sp["metadata_url"].(string), "https://iam.example"), nil)
	if err := idp.Trust([]byte(metadata.Body)); err != nil {
		t.Fatal(err)
	}
	entity := sp["entity_id"].(string)
	user := samltest.User{NameID: "00u-carol", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "carol@example.com", Name: "Carol"}
	unsolicited := func(relay string) samltest.Form {
		t.Helper()
		form, err := idp.Unsolicited(entity, relay, user)
		if err != nil {
			t.Fatal(err)
		}
		return form
	}
	var spent int
	sessions := func() int {
		var n int
		if err := e.DB.Get(&n, `SELECT count(*) FROM sessions`); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := sessions()
	status, _, body := e.acsRaw(unsolicited("").SAMLResponse, "")
	if status != 400 || !strings.Contains(body, "IDP_INITIATED_DISABLED") {
		t.Fatalf("not enabled: %d %s", status, body)
	}
	// Only a response the connection's IdP signed learns the option is off:
	// a forged one and one for an unknown connection get the same generic 401.
	forger := samltest.New("https://idp.example.com")
	_ = forger.Trust([]byte(metadata.Body))
	forgedOff, err := forger.Unsolicited(entity, "", user)
	if err != nil {
		t.Fatal(err)
	}
	status, _, forgedBody := e.acsRaw(forgedOff.SAMLResponse, "")
	if status != 401 || strings.Contains(forgedBody, "IDP_INITIATED_DISABLED") {
		t.Fatalf("forged response, option off: %d %s", status, forgedBody)
	}
	unknown := strings.Replace(entity, conn, "00000000-0000-4000-8000-00000000dead", 1)
	if unknown == entity {
		t.Fatalf("entity %q does not embed the connection", entity)
	}
	if err := idp.Trust([]byte(strings.Replace(metadata.Body, entity, unknown, -1))); err != nil {
		t.Fatal(err)
	}
	ghost, err := idp.Unsolicited(unknown, "", user)
	if err != nil {
		t.Fatal(err)
	}
	status, _, ghostBody := e.acsRaw(ghost.SAMLResponse, "")
	if status != 401 || strings.Contains(ghostBody, "IDP_INITIATED_DISABLED") {
		t.Fatalf("unknown connection: %d %s", status, ghostBody)
	}

	// Option validation: a client that exists, has an initiate_login_uri.
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent", "idp_initiated_client_id": "not-a-client"}}, 400)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent", "idp_initiated_client_id": "00000000-0000-4000-8000-000000000000"}}, 400)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent", "idp_initiated_client_id": plainID}}, 400)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent", "idp_initiated_client_id": appID}}, 204)
	if o := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON["options"].(map[string]any); o["idp_initiated_client_id"] != appID {
		t.Fatalf("options = %v", o)
	}
	// Other providers do not take the option.
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Bad", "provider": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret": "s", "options": fiber.Map{"idp_initiated_client_id": appID}}, 400)

	// An IdP-initiated response: 303 to the client's sign-in endpoint with the
	// connection, its organization and this issuer; the endpoint's query is
	// kept. No session, no user.
	form := unsolicited("")
	status, location, _ := e.acsRaw(form.SAMLResponse, "")
	if status != 303 {
		t.Fatalf("idp-initiated: %d %q", status, location)
	}
	target, err := url.Parse(location)
	if err != nil || target.Host != "app.example" || target.Path != "/login" {
		t.Fatalf("location = %q %v", location, err)
	}
	if q := target.Query(); q.Get("tenant") != "acme" || q.Get("connection_id") != conn || q.Get("organization_id") != e.Org || q.Get("iss") != "https://iam.example" || q.Get("target_link_uri") != "" || q.Get("code") != "" {
		t.Fatalf("location query = %v", q)
	}
	if after := sessions(); after != before {
		t.Fatalf("sessions %d -> %d: an unsolicited response must not sign anybody in", before, after)
	}
	var users int
	if err := e.DB.Get(&users, `SELECT count(*) FROM users WHERE email='carol@example.com'`); err != nil || users != 0 {
		t.Fatalf("user created by an unsolicited response: %d %v", users, err)
	}
	if err := e.DB.Get(&spent, `SELECT count(*) FROM events WHERE type='connection.idp_initiated' AND subject_id=$1 AND data->>'client_id'=$2`, conn, appID); err != nil || spent != 1 {
		t.Fatalf("event: %d %v", spent, err)
	}
	// Replay, tampered signature and a response signed by another key.
	if status, _, _ := e.acsRaw(form.SAMLResponse, ""); status != 401 {
		t.Fatalf("replay: %d", status)
	}
	if status, _, _ := e.acsRaw(form.SAMLResponse, "client_id="+second); status != 401 {
		t.Fatalf("replay with relay state: %d", status)
	}
	raw, _ := base64.StdEncoding.DecodeString(unsolicited("").SAMLResponse)
	if !strings.Contains(string(raw), "00u-carol") {
		t.Fatal("name id not in the response")
	}
	tampered := base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), "00u-carol", "00u-admin", 1)))
	if status, _, _ := e.acsRaw(tampered, ""); status != 401 {
		t.Fatalf("tampered: %d", status)
	}
	forged, err := forger.Unsolicited(entity, "", user)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _ := e.acsRaw(forged.SAMLResponse, ""); status != 401 {
		t.Fatalf("forged: %d", status)
	}
	// Garbage and a solicited-looking response (InResponseTo) never pass.
	if status, _, _ := e.acsRaw("not-base64!", ""); status != 401 && status != 400 {
		t.Fatalf("garbage: %d", status)
	}
	redirect, _ := e.samlStart(conn)
	solicited, err := idp.Answer(redirect, user)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _ := e.acsRaw(solicited.SAMLResponse, ""); status != 401 {
		t.Fatalf("solicited response without state: %d", status)
	}

	// RelayState: client_id honoured when it is a usable client, redirect_uri
	// when registered on it; everything else ignored.
	status, location, _ = e.acsRaw(unsolicited("").SAMLResponse, "client_id="+second+"&redirect_uri=https%3A%2F%2Fapp.example%2Fother")
	if status != 303 || !strings.HasPrefix(location, "https://second.example/sso?") || strings.Contains(location, "target_link_uri") {
		t.Fatalf("relay client (redirect not registered on it): %d %q", status, location)
	}
	status, location, _ = e.acsRaw(unsolicited("").SAMLResponse, "client_id="+appID+"&redirect_uri=https%3A%2F%2Fapp.example%2Fother&utm=1&organization_id=evil&connection_id=evil")
	target, _ = url.Parse(location)
	if status != 303 || target.Host != "app.example" || target.Query().Get("target_link_uri") != "https://app.example/other" || target.Query().Get("connection_id") != conn || target.Query().Get("organization_id") != e.Org || target.Query().Get("utm") != "" {
		t.Fatalf("relay redirect: %d %q", status, location)
	}
	status, location, _ = e.acsRaw(unsolicited("").SAMLResponse, "redirect_uri=https%3A%2F%2Fevil.example%2Fcb")
	if status != 303 || strings.Contains(location, "evil") || strings.Contains(location, "target_link_uri") {
		t.Fatalf("unregistered redirect: %d %q", status, location)
	}
	// An unusable client in the RelayState falls back to the connection's.
	for _, relay := range []string{"client_id=" + plainID, "client_id=00000000-0000-4000-8000-000000000000", "client_id=nope", "https://app.example/dashboard", "a=b"} {
		status, location, _ = e.acsRaw(unsolicited("").SAMLResponse, relay)
		if status != 303 || !strings.HasPrefix(location, "https://app.example/login?") {
			t.Fatalf("relay %q: %d %q", relay, status, location)
		}
	}

	// The sign-in endpoint starts the ordinary login: /oauth/authorize with
	// connection_id skips the identifier step and goes to the IdP; the
	// SP-initiated response then signs in and the code is redeemed.
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Everyone"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"jit_group_id": group}, 204)
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)

	b := e.browser()
	start := b.authorizeWith(appID, url.Values{"connection_id": {conn}, "organization_id": {e.Org}})
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=ik_authorize_") {
		t.Fatalf("authorize with connection: %d %q %s", start.Status, start.Location, start.Body)
	}
	hop := b.get(start.Location)
	if hop.Status != 303 || !strings.HasPrefix(hop.Location, "https://idp.example.com/sso?SAMLRequest=") {
		t.Fatalf("hosted login with a connection hint: %d %q %s", hop.Status, hop.Location, hop.Body)
	}
	// The hint is followed once per ticket: back and start-over links return
	// to the same page, which then offers the ordinary sign-in.
	if again := b.get(start.Location); again.Status != 200 || again.field("ticket") == "" || !strings.Contains(again.Body, `name="email"`) {
		t.Fatalf("second visit with a connection hint: %d %q %s", again.Status, again.Location, again.Body)
	}
	answer, err := idp.Answer(hop.Location, user)
	if err != nil {
		t.Fatal(err)
	}
	parked := b.post("/identity/v1/federation/saml/acs", url.Values{"SAMLResponse": {answer.SAMLResponse}, "RelayState": {answer.RelayState}})
	if parked.Status != 303 {
		t.Fatalf("acs: %d %s", parked.Status, parked.Body)
	}
	tokens := b.exchange(appID, b.get(parked.Location))
	if c := claims(t, tokens["access_token"].(string)); c["organization_id"] != e.Org {
		t.Fatalf("claims = %v", c)
	}

	// Hints that cannot be used show the ordinary sign-in; a malformed one is
	// a bad request.
	other := e.browser()
	for _, hint := range []string{"00000000-0000-4000-8000-000000000000"} {
		page := other.authorizeWith(appID, url.Values{"connection_id": {hint}})
		if page.Status != 303 {
			t.Fatalf("unknown hint authorize: %d %s", page.Status, page.Body)
		}
		if login := other.get(page.Location); login.Status != 200 || login.field("ticket") == "" {
			t.Fatalf("unknown hint login: %d %s", login.Status, login.Body)
		}
	}
	if bad := e.browser().authorizeWith(appID, url.Values{"connection_id": {"nope"}}); bad.Status != 400 && bad.Status != 303 {
		t.Fatalf("malformed hint: %d", bad.Status)
	}
	// An organization hint of another organization keeps the hint unused.
	if foreign := e.browser(); true {
		page := foreign.authorizeWith(appID, url.Values{"connection_id": {conn}, "organization_id": {"00000000-0000-4000-8000-000000000001"}})
		if page.Status == 303 {
			if login := foreign.get(page.Location); login.Status == 303 && strings.HasPrefix(login.Location, "https://idp.example.com") {
				t.Fatalf("connection of another organization started: %q", login.Location)
			}
		}
	}

	// Turning it off (or removing the client) refuses IdP-initiated again.
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent"}}, 204)
	if status, _, body := e.acsRaw(unsolicited("").SAMLResponse, ""); status != 400 || !strings.Contains(body, "IDP_INITIATED_DISABLED") {
		t.Fatalf("after removing the option: %d %s", status, body)
	}
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent", "idp_initiated_client_id": appID}}, 204)
	e.Must("PATCH", clients+"/"+app["id"].(string), e.Owner, fiber.Map{"initiate_login_uri": ""}, 204)
	if status, _, body := e.acsRaw(unsolicited("").SAMLResponse, ""); status != 400 || !strings.Contains(body, "IDP_INITIATED_DISABLED") {
		t.Fatalf("client without sign-in endpoint: %d %s", status, body)
	}
}
