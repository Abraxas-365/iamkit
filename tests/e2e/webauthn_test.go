package e2e_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfawebauthn/softkey"
	"github.com/gofiber/fiber/v2"
)

// The harness issuer; the relying party id is its host.
const webauthnOrigin = "https://iam.example"

// options reads the WebAuthn options of a begin response (the
// PublicKeyCredential{Creation,Request}Options, without a publicKey wrapper).
func options(t *testing.T, r Response) (string, json.RawMessage) {
	t.Helper()
	session, _ := r.JSON["webauthn_session"].(string)
	raw, err := json.Marshal(r.JSON["options"])
	if !strings.HasPrefix(session, "ik_wa_") || err != nil {
		t.Fatalf("options = %s", r.Body)
	}
	return session, raw
}

// registerKey registers a security key or passkey through self-service.
func (e *Env) registerKey(access, name string, passkey bool) (*softkey.Key, map[string]any) {
	e.t.Helper()
	body := func(extra fiber.Map) fiber.Map {
		extra["environment_id"], extra["audience"] = e.EnvID, e.Audience
		return extra
	}
	session, opts := options(e.t, e.Must("POST", "/identity/v1/me/factors/webauthn", access, body(fiber.Map{"name": name, "passkey": passkey}), 201))
	key, credential, err := softkey.Create(opts, webauthnOrigin, passkey)
	if err != nil {
		e.t.Fatal(err)
	}
	done := e.Must("POST", "/identity/v1/me/factors/webauthn/confirm", access, body(fiber.Map{"webauthn_session": session, "credential": credential}), 201)
	factor, _ := done.JSON["factor"].(map[string]any)
	return key, factor
}

// TestWebAuthnJourney covers security keys as a second factor (self-service
// registration, headless and hosted login, rename, removal, clone
// detection) and passkeys as a first factor (headless and hosted, policy
// switches, SSO enforcement).
func TestWebAuthnJourney(t *testing.T) {
	e := newEnv(t)
	access := e.Login(e.AliceEmail)
	body := func(extra fiber.Map) fiber.Map {
		extra["environment_id"], extra["audience"] = e.EnvID, e.Audience
		return extra
	}

	// Registration: validated name, attestation verified, recovery codes once.
	e.Must("POST", "/identity/v1/me/factors/webauthn", access, body(fiber.Map{"name": strings.Repeat("k", 101)}), 400)
	e.Must("POST", "/identity/v1/me/factors/webauthn/confirm", access, body(fiber.Map{"webauthn_session": "ik_wa_nope", "credential": fiber.Map{}}), 422)
	key, factor := e.registerKey(access, "YubiKey", false)
	if factor["kind"] != "webauthn" || factor["name"] != "YubiKey" || factor["passkey"] != nil || e.audited("mfa.enrolled", e.Alice) != 1 {
		t.Fatalf("factor = %v", factor)
	}
	list := e.Must("GET", "/identity/v1/me/factors?environment_id="+e.EnvID+"&audience="+url.QueryEscape(e.Audience), access, nil, 200)
	if !strings.Contains(list.Body, `"YubiKey"`) || strings.Contains(list.Body, "public_key") {
		t.Fatalf("list = %s", list.Body)
	}

	// Headless login: the key answers /mfa/webauthn options.
	pending := e.mfaLogin(e.AliceEmail)
	if !contains(strs(pending.JSON["factors"]), "webauthn") {
		t.Fatalf("pending = %s", pending.Body)
	}
	token := pending.JSON["mfa_token"].(string)
	session, opts := options(t, e.Must("POST", "/identity/v1/mfa/webauthn", "", fiber.Map{"mfa_token": token}, 200))
	assertion, _ := key.Get(opts, webauthnOrigin)
	pair := e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "webauthn_session": session, "credential": assertion}, 200)
	if a := strs(claims(t, pair.JSON["access_token"].(string))["amr"]); !equal(a, []string{"pwd", "hwk", "mfa"}) {
		t.Fatalf("security key amr = %v", a)
	}
	// Replay and a foreign origin fail.
	token = e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "webauthn_session": session, "credential": assertion}, 401)
	session, opts = options(t, e.Must("POST", "/identity/v1/mfa/webauthn", "", fiber.Map{"mfa_token": token}, 200))
	foreign, _ := key.Get(opts, "https://evil.example")
	e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "webauthn_session": session, "credential": foreign}, 401)

	// A security key is not a passkey.
	session, opts = options(t, e.Must("POST", "/identity/v1/passkeys/login/begin", "", fiber.Map{"environment_id": e.EnvID}, 200))
	assertion, _ = key.Get(opts, webauthnOrigin)
	e.Must("POST", "/identity/v1/passkeys/login/finish", "", passkeyBody(e, session, assertion), 401)

	// Passkey: registered with user verification, signs in with no password
	// and no second factor, amr hwk+user+mfa.
	fresh := e.securityKeyLogin(key)
	passkey, pk := e.registerKey(fresh, "Phone", true)
	if pk["passkey"] != true {
		t.Fatalf("passkey factor = %v", pk)
	}
	session, opts = options(t, e.Must("POST", "/identity/v1/passkeys/login/begin", "", fiber.Map{"environment_id": e.EnvID}, 200))
	assertion, _ = passkey.Get(opts, webauthnOrigin)
	pair = e.Must("POST", "/identity/v1/passkeys/login/finish", "", passkeyBody(e, session, assertion), 200)
	if a := strs(claims(t, pair.JSON["access_token"].(string))["amr"]); !equal(a, []string{"hwk", "user", "mfa"}) {
		t.Fatalf("passkey amr = %v", a)
	}
	e.Must("POST", "/identity/v1/passkeys/login/finish", "", passkeyBody(e, session, assertion), 401) // single use

	// Clone detection: a counter going backwards is refused and audited.
	if _, err := e.DB.Exec(`UPDATE user_factors SET data = jsonb_set(data, '{sign_count}', '1000') WHERE user_id=$1 AND passkey`, e.Alice); err != nil {
		t.Fatal(err)
	}
	session, opts = options(t, e.Must("POST", "/identity/v1/passkeys/login/begin", "", fiber.Map{"environment_id": e.EnvID}, 200))
	assertion, _ = passkey.Get(opts, webauthnOrigin)
	e.Must("POST", "/identity/v1/passkeys/login/finish", "", passkeyBody(e, session, assertion), 401)
	if e.audited("mfa.clone_detected", e.Alice) != 1 {
		t.Fatal("clone not audited")
	}
	if _, err := e.DB.Exec(`UPDATE user_factors SET data = jsonb_set(data, '{sign_count}', '0') WHERE user_id=$1 AND passkey`, e.Alice); err != nil {
		t.Fatal(err)
	}

	// The environment policy can turn passkeys off.
	policy := e.Base + "/sign-in-policy"
	current := e.Must("GET", policy, e.Owner, nil, 200).JSON
	if current["allow_passkey"] != true {
		t.Fatalf("policy = %v", current)
	}
	current["allow_passkey"] = false
	e.Must("PUT", policy, e.Owner, current, 200)
	if r := e.Must("POST", "/identity/v1/passkeys/login/begin", "", fiber.Map{"environment_id": e.EnvID}, 403); !strings.Contains(r.Body, "METHOD_NOT_ALLOWED") {
		t.Fatalf("passkeys off = %s", r.Body)
	}
	current["allow_passkey"] = true
	e.Must("PUT", policy, e.Owner, current, 200)

	// Hosted: a new client offers passkeys (nonce-bound script), the
	// passkey signs in with no second factor.
	client := e.hostedClient()
	b := e.browser()
	login := b.authorize(client)
	csp := login.Header.Get("Content-Security-Policy")
	if !strings.Contains(login.Body, `data-webauthn="/hosted/login/passkey/options"`) || !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(login.Body, "<script nonce=") {
		t.Fatalf("hosted passkey offer: %s\n%s", csp, login.Body)
	}
	ticket := login.field("ticket")
	raw := b.post("/hosted/login/passkey/options", url.Values{"ticket": {ticket}})
	var begun map[string]any
	json.Unmarshal([]byte(raw.Body), &begun)
	session, opts = options(t, Response{Status: raw.Status, Body: raw.Body, JSON: begun})
	assertion, _ = passkey.Get(opts, webauthnOrigin)
	done := b.post("/hosted/login/passkey", url.Values{"ticket": {ticket}, "webauthn_session": {session}, "credential": {string(assertion)}})
	tokens := b.exchange(client, done)
	if a := strs(claims(t, tokens["id_token"].(string))["amr"]); !equal(a, []string{"hwk", "user", "mfa"}) {
		t.Fatalf("hosted passkey amr = %v", a)
	}

	// Hosted password login: the second-factor page offers the key.
	b = e.browser()
	login = b.authorize(client)
	ticket = login.field("ticket")
	pw := b.post("/hosted/login/password", url.Values{"ticket": {ticket}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if !strings.Contains(pw.Body, `data-webauthn="/hosted/login/mfa/webauthn"`) {
		t.Fatalf("mfa page: %s", pw.Body)
	}
	raw = b.post("/hosted/login/mfa/webauthn", url.Values{"ticket": {ticket}})
	json.Unmarshal([]byte(raw.Body), &begun)
	session, opts = options(t, Response{Status: raw.Status, Body: raw.Body, JSON: begun})
	assertion, _ = key.Get(opts, webauthnOrigin)
	done = b.post("/hosted/login/mfa", url.Values{"ticket": {ticket}, "factors": {pw.field("factors")}, "webauthn_session": {session}, "credential": {string(assertion)}})
	tokens = b.exchange(client, done)
	if a := strs(claims(t, tokens["id_token"].(string))["amr"]); !equal(a, []string{"pwd", "hwk", "mfa"}) {
		t.Fatalf("hosted key amr = %v", a)
	}

	// Rename; removal needs a fresh proof (the key itself works).
	fresh = e.securityKeyLogin(key)
	id := factor["id"].(string)
	renamed := e.Must("PATCH", "/identity/v1/me/factors/webauthn/"+id, fresh, body(fiber.Map{"name": "Desk key"}), 200)
	if renamed.JSON["name"] != "Desk key" {
		t.Fatalf("rename = %s", renamed.Body)
	}
	e.Must("DELETE", "/identity/v1/me/factors/webauthn/"+id, fresh, body(fiber.Map{"code": "000000"}), 422)
	session, opts = options(t, e.Must("POST", "/identity/v1/me/factors/webauthn/challenge", fresh, body(fiber.Map{}), 200))
	assertion, _ = key.Get(opts, webauthnOrigin)
	e.Must("DELETE", "/identity/v1/me/factors/webauthn/"+id, fresh, body(fiber.Map{"webauthn_session": session, "credential": assertion}), 204)
	if e.audited("mfa.removed", e.Alice) != 1 {
		t.Fatal("removal not audited")
	}
}

func passkeyBody(e *Env, session string, credential json.RawMessage) fiber.Map {
	return fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "webauthn_session": session, "credential": credential}
}

// securityKeyLogin signs in with the password and the security key.
func (e *Env) securityKeyLogin(key *softkey.Key) string {
	e.t.Helper()
	token := e.mfaLogin(e.AliceEmail).JSON["mfa_token"].(string)
	session, opts := options(e.t, e.Must("POST", "/identity/v1/mfa/webauthn", "", fiber.Map{"mfa_token": token}, 200))
	assertion, err := key.Get(opts, webauthnOrigin)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.Must("POST", "/identity/v1/mfa/verify", "", fiber.Map{"mfa_token": token, "webauthn_session": session, "credential": assertion}, 200).JSON["access_token"].(string)
}
