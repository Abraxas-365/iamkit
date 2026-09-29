package e2e_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// deviceRequest posts form to /oauth/device_authorization.
func (e *Env) deviceRequest(form url.Values) Response {
	e.t.Helper()
	req := httptest.NewRequest("POST", "/oauth/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := Response{Status: res.StatusCode, Body: string(raw)}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

// TestDeviceAuthorizationGrant covers RFC 8628 end to end: a device-only
// hosted client gets a device and user code, polls (pending, slow down),
// the user approves at /hosted/device through the ordinary hosted login,
// and the device collects tokens once; denial, unknown codes and clients
// without the grant are refused.
func TestDeviceAuthorizationGrant(t *testing.T) {
	e := newEnv(t)
	e.t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	grants := []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}

	// The device grant needs hosted login; a device-only client needs no
	// redirect URIs.
	e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "public": true, "grant_types": grants}, 400)
	client := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res, "public": true, "hosted_login": true, "grant_types": grants}, 201).JSON["client_id"].(string)
	view := e.Must("GET", e.Base+"/oauth-clients/"+client, e.Owner, nil, 200).JSON
	if got := view["grant_types"].([]any); len(got) != 2 || got[0] != grants[0] {
		t.Fatalf("grant_types = %v", view["grant_types"])
	}
	// Turning hosted login off would strand the device grant.
	e.Must("PATCH", e.Base+"/oauth-clients/"+client, e.Owner, fiber.Map{"hosted_login": false}, 400)

	discovery := e.Must("GET", "/.well-known/openid-configuration", "", nil, 200)
	if !strings.HasSuffix(discovery.JSON["device_authorization_endpoint"].(string), "/oauth/device_authorization") || !strings.Contains(discovery.Body, grants[0]) {
		t.Fatalf("discovery = %s", discovery.Body)
	}

	// A code-flow client may not start device authorizations.
	codeClient := e.hostedClient()
	if r := e.deviceRequest(url.Values{"client_id": {codeClient}}); r.Status != 400 || r.JSON["error"] != "unauthorized_client" {
		t.Fatalf("code client: %d %s", r.Status, r.Body)
	}
	if r := e.deviceRequest(url.Values{"client_id": {client}, "scope": {"openid admin"}}); r.Status != 400 || r.JSON["error"] != "invalid_scope" {
		t.Fatalf("bad scope: %d %s", r.Status, r.Body)
	}

	start := e.deviceRequest(url.Values{"client_id": {client}, "scope": {"openid offline_access"}})
	if start.Status != 200 || start.JSON["interval"].(float64) != 5 || start.JSON["expires_in"].(float64) != 600 || !strings.HasSuffix(start.JSON["verification_uri"].(string), "/hosted/device") {
		t.Fatalf("device authorization: %d %s", start.Status, start.Body)
	}
	deviceCode, userCode := start.JSON["device_code"].(string), start.JSON["user_code"].(string)
	if len(userCode) != 9 || userCode[4] != '-' || !strings.Contains(start.JSON["verification_uri_complete"].(string), "user_code="+userCode) {
		t.Fatalf("user code = %q", userCode)
	}
	poll := url.Values{"grant_type": {grants[0]}, "client_id": {client}, "device_code": {deviceCode}}
	if r := e.tokenRequest(poll, "", ""); r.Status != 400 || r.JSON["error"] != "authorization_pending" {
		t.Fatalf("pending: %d %s", r.Status, r.Body)
	}
	if r := e.tokenRequest(poll, "", ""); r.Status != 400 || r.JSON["error"] != "slow_down" {
		t.Fatalf("slow down: %d %s", r.Status, r.Body)
	}
	// Another client cannot redeem the code.
	if r := e.tokenRequest(url.Values{"grant_type": {grants[0]}, "client_id": {codeClient}, "device_code": {deviceCode}}, "", ""); r.Status != 400 || r.JSON["error"] != "unauthorized_client" {
		t.Fatalf("other client: %d %s", r.Status, r.Body)
	}

	// The user types the code, sees the application, and signs in.
	b := e.browser()
	if p := b.get("/hosted/device?user_code=" + url.QueryEscape(userCode)); p.Status != 200 || !strings.Contains(p.Body, userCode) {
		t.Fatalf("device page: %d %s", p.Status, p.Body)
	}
	if p := b.post("/hosted/device", url.Values{"user_code": {"BCDF-GHJK"}}); p.Status != 404 {
		t.Fatalf("unknown code: %d", p.Status)
	}
	confirm := b.post("/hosted/device", url.Values{"user_code": {strings.ToLower(userCode)}})
	if confirm.Status != 200 || confirm.field("user_code") != userCode || !strings.Contains(confirm.Body, "offline_access") {
		t.Fatalf("confirm: %d %s", confirm.Status, confirm.Body)
	}
	approve := b.post("/hosted/device/approve", url.Values{"user_code": {userCode}})
	if approve.Status != 303 || !strings.HasPrefix(approve.Location, "/hosted/login?ticket=ik_authorize_") {
		t.Fatalf("approve: %d %q %s", approve.Status, approve.Location, approve.Body)
	}
	login := b.get(approve.Location)
	tk := login.field("ticket")
	b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	done := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if done.Status != 200 || !strings.Contains(done.Body, "Device connected") {
		t.Fatalf("finish: %d %q %s", done.Status, done.Location, done.Body)
	}
	var audits int
	e.DB.Get(&audits, `SELECT count(*) FROM audit_events WHERE action='oauth.device_approved' AND actor_id=$1`, e.Alice)
	if audits != 1 {
		t.Fatalf("device_approved audits = %d", audits)
	}

	// The device collects its tokens once (after waiting its interval).
	e.DB.MustExec(`UPDATE oauth_device_codes SET last_poll_at=now()-interval '1 minute'`)
	tokens := e.tokenRequest(poll, "", "")
	if tokens.Status != 200 || tokens.JSON["access_token"] == nil || tokens.JSON["id_token"] == nil || tokens.JSON["refresh_token"] == nil {
		t.Fatalf("tokens: %d %s", tokens.Status, tokens.Body)
	}
	access := claims(t, tokens.JSON["access_token"].(string))
	if access["sub"] != e.Alice || access["organization_id"] != e.Org || access["oauth_client_id"] != client || access["application_id"] != e.Client {
		t.Fatalf("access claims = %v", access)
	}
	if !equal(e.permissions(tokens.JSON["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatal("device token lacks permissions")
	}
	id := claims(t, tokens.JSON["id_token"].(string))
	if id["sub"] != e.Alice || id["aud"].([]any)[0] != client || id["sid"] != access["sid"] {
		t.Fatalf("id claims = %v", id)
	}
	var bound string
	e.DB.Get(&bound, `SELECT oauth_client_id FROM sessions WHERE id=$1`, access["sid"])
	if bound != client {
		t.Fatalf("session client = %q", bound)
	}
	e.DB.MustExec(`UPDATE oauth_device_codes SET last_poll_at=now()-interval '1 minute'`)
	if r := e.tokenRequest(poll, "", ""); r.Status != 400 || r.JSON["error"] != "invalid_grant" {
		t.Fatalf("second redemption: %d %s", r.Status, r.Body)
	}
	// The refresh token works like any other.
	refreshed := e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {tokens.JSON["refresh_token"].(string)}}, "", "")
	if refreshed.Status != 200 || refreshed.JSON["access_token"] == nil {
		t.Fatalf("refresh: %d %s", refreshed.Status, refreshed.Body)
	}

	// Denied devices get access_denied; approved codes cannot be reused.
	denied := e.deviceRequest(url.Values{"client_id": {client}})
	b = e.browser()
	if p := b.post("/hosted/device/deny", url.Values{"user_code": {denied.JSON["user_code"].(string)}}); p.Status != 200 {
		t.Fatalf("deny: %d %s", p.Status, p.Body)
	}
	if p := b.post("/hosted/device", url.Values{"user_code": {userCode}}); p.Status != 404 {
		t.Fatalf("spent code: %d", p.Status)
	}
	if r := e.tokenRequest(url.Values{"grant_type": {grants[0]}, "client_id": {client}, "device_code": {denied.JSON["device_code"].(string)}}, "", ""); r.Status != 400 || r.JSON["error"] != "access_denied" {
		t.Fatalf("denied: %d %s", r.Status, r.Body)
	}

	// Expired codes answer expired_token.
	expired := e.deviceRequest(url.Values{"client_id": {client}})
	e.DB.MustExec(`UPDATE oauth_device_codes SET expires_at=now()-interval '1 second' WHERE status='pending'`)
	if r := e.tokenRequest(url.Values{"grant_type": {grants[0]}, "client_id": {client}, "device_code": {expired.JSON["device_code"].(string)}}, "", ""); r.Status != 400 || r.JSON["error"] != "expired_token" {
		t.Fatalf("expired: %d %s", r.Status, r.Body)
	}

	// Existing clients keep the authorization code grants; adding the
	// device grant to one is a PATCH.
	codeView := e.Must("GET", e.Base+"/oauth-clients/"+codeClient, e.Owner, nil, 200).JSON
	if got := codeView["grant_types"].([]any); len(got) != 2 || got[0] != "authorization_code" {
		t.Fatalf("default grant_types = %v", got)
	}
	e.Must("PATCH", e.Base+"/oauth-clients/"+codeClient, e.Owner, fiber.Map{"grant_types": []string{"authorization_code", "refresh_token", grants[0]}}, 204)
	if r := e.deviceRequest(url.Values{"client_id": {codeClient}}); r.Status != 200 {
		t.Fatalf("patched client: %d %s", r.Status, r.Body)
	}
	e.Must("PATCH", e.Base+"/oauth-clients/"+codeClient, e.Owner, fiber.Map{"grant_types": []string{"refresh_token"}}, 400)
}
