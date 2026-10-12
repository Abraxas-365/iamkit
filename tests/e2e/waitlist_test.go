package e2e_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// waitlistEnv turns sign-up and the waitlist on for the environment.
func waitlistEnv(e *Env, extra fiber.Map) {
	e.t.Helper()
	body := fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true, "allow_password_reset": true,
		"allow_signup": true, "signup_organization_id": e.Org, "waitlist": true,
		"waitlist_signup_url": "https://app.example.com/signup"}
	for k, v := range extra {
		body[k] = v
	}
	e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, body, 200)
}

func (e *Env) waitlistMail(purpose string) int {
	n := 0
	for _, m := range e.Mail.Sent {
		if m.Purpose == purpose {
			n++
		}
	}
	return n
}

// TestWaitlistJourney: join → list → approve → sign up with the token →
// complete → completed; reject (silent / notify); delete frees the email;
// hosted pages; every answer to a join looks the same.
func TestWaitlistJourney(t *testing.T) {
	e := newEnv(t)
	base := e.Base + "/waitlist"
	signup := func(email, token string) Response {
		body := fiber.Map{"environment_id": e.EnvID, "email": email, "name": "Wait Person", "password": "a long enough password"}
		if token != "" {
			body["waitlist_token"] = token
		}
		return e.Do("POST", "/identity/v1/signup", "", body)
	}
	verify := func(challenge any, code string) Response {
		return e.Do("POST", "/identity/v1/signup/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": challenge, "code": code})
	}
	entries := func(query string) []any {
		return e.Must("GET", base+query, e.Owner, nil, 200).JSON["items"].([]any)
	}

	// Waitlist needs allow_signup.
	e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, fiber.Map{"allow_password": true, "allow_email_code": true, "waitlist": true}, 400)
	// Off: sign-up behaves as before (a code, status code_sent).
	e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true,
		"allow_password_reset": true, "allow_signup": true, "signup_organization_id": e.Org}, 200)
	r := signup("off@example.com", "")
	if r.Status != 202 || r.JSON["status"] != "code_sent" || e.waitlistMail("email_verification") != 1 || e.waitlistMail("waitlist_joined") != 0 {
		t.Fatalf("off: %d %s", r.Status, r.Body)
	}
	if n := len(entries("")); n != 0 {
		t.Fatalf("entries with the waitlist off: %d", n)
	}

	waitlistEnv(e, fiber.Map{"waitlist_auto_approve_domains": []string{"vip.example"}})
	// A PUT that omits the waitlist fields (an older client) keeps them:
	// the gate never opens by omission.
	kept := e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, fiber.Map{"allow_password": true, "allow_email_code": true, "allow_social": true,
		"allow_password_reset": true, "allow_signup": true, "signup_organization_id": e.Org}, 200)
	if kept.JSON["waitlist"] != true || kept.JSON["waitlist_signup_url"] != "https://app.example.com/signup" ||
		len(kept.JSON["waitlist_auto_approve_domains"].([]any)) != 1 {
		t.Fatalf("omitted waitlist fields not kept: %s", kept.Body)
	}
	waitlistEnv(e, fiber.Map{"waitlist_auto_approve_domains": []string{}})

	// A join: same 202 shape, no code, one joined email, a pending entry.
	codes := e.waitlistMail("email_verification")
	r = signup("Ada@Example.com", "")
	if r.Status != 202 || r.JSON["status"] != "waitlisted" || r.JSON["challenge_id"] == "" || r.JSON["expires_in"] == nil {
		t.Fatalf("join: %d %s", r.Status, r.Body)
	}
	e.Server.WaitDeliveries(5 * 1e9)
	if e.waitlistMail("email_verification") != codes || e.waitlistMail("waitlist_joined") != 1 {
		t.Fatalf("mail: codes=%d joined=%d", e.waitlistMail("email_verification")-codes, e.waitlistMail("waitlist_joined"))
	}
	if v := verify(r.JSON["challenge_id"], "12345678"); v.Status != 401 {
		t.Fatalf("a waitlisted challenge verified: %d %s", v.Status, v.Body)
	}
	// Anti-enumeration: an existing entry and an existing account answer the
	// same and send nothing more.
	again := signup("ada@example.com", "")
	account := signup(e.AliceEmail, "")
	for name, got := range map[string]Response{"again": again, "account": account} {
		if got.Status != 202 || got.JSON["status"] != "waitlisted" || got.JSON["message"] != r.JSON["message"] || got.JSON["challenge_id"] == "" {
			t.Fatalf("%s: %d %s", name, got.Status, got.Body)
		}
	}
	e.Server.WaitDeliveries(5 * 1e9)
	if e.waitlistMail("waitlist_joined") != 1 || count(t, e.DB, `SELECT count(*) FROM waitlist_entries WHERE environment_id=$1`, e.EnvID) != 1 {
		t.Fatal("duplicate joins created entries or mail")
	}

	// The list, one entry and the filters.
	list := entries("")
	if len(list) != 1 {
		t.Fatalf("list: %v", list)
	}
	entry := list[0].(map[string]any)
	id, _ := entry["id"].(string)
	if entry["email"] != "ada@example.com" || entry["status"] != "pending" || id == "" || entry["token_hash"] != nil || entry["token"] != nil {
		t.Fatalf("entry: %v", entry)
	}
	if n := len(entries("?status=approved")); n != 0 {
		t.Fatalf("approved filter: %d", n)
	}
	if n := len(entries("?status=pending&email=ADA")); n != 1 {
		t.Fatalf("email filter: %d", n)
	}
	e.Must("GET", base+"?status=bogus", e.Owner, nil, 400)
	if got := e.Must("GET", base+"/"+id, e.Owner, nil, 200).JSON; got["id"] != id {
		t.Fatalf("find: %v", got)
	}
	e.Must("GET", base+"/00000000-0000-4000-8000-000000000000", e.Owner, nil, 404)
	e.Must("GET", base+"/not-a-uuid", e.Owner, nil, 404)

	// Approve: status, expiry, and an email with the sign-up link.
	approved := e.Must("POST", base+"/"+id+"/approve", e.Owner, nil, 200).JSON
	if approved["status"] != "approved" || approved["expires_at"] == nil || approved["decided_by"] == "" {
		t.Fatalf("approve: %v", approved)
	}
	e.Server.WaitDeliveries(5 * 1e9)
	mail, ok := e.Mail.Last("waitlist_approved")
	if !ok || mail.Email != "ada@example.com" || !strings.HasPrefix(mail.Token, "ik_wait_") ||
		mail.Link != "https://app.example.com/signup?waitlist="+mail.Token {
		t.Fatalf("approval mail: %+v", mail)
	}
	token := mail.Token

	// The token only works for its own address.
	if r = signup("other@example.com", token); r.Status != 202 || r.JSON["status"] != "waitlisted" {
		t.Fatalf("token for another address: %d %s", r.Status, r.Body)
	}
	// Hosted: the sign-up page prefills the address for a valid token and
	// shows a plain form for a bad one.
	client := e.hostedClient()
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	page := b.get("/hosted/signup?ticket=" + url.QueryEscape(tk) + "&waitlist=" + url.QueryEscape(token))
	if page.Status != 200 || !strings.Contains(page.Body, "ada@example.com") || !strings.Contains(page.Body, `name="waitlist"`) {
		t.Fatalf("hosted prefill: %d %s", page.Status, page.Body)
	}
	bad := b.get("/hosted/signup?ticket=" + url.QueryEscape(tk) + "&waitlist=ik_wait_nope")
	if bad.Status != 200 || strings.Contains(bad.Body, "ada@example.com") || strings.Contains(bad.Body, `name="waitlist"`) {
		t.Fatalf("hosted bad token: %d %s", bad.Status, bad.Body)
	}
	// Hosted join: the waitlisted page.
	joined := b.post("/hosted/signup", url.Values{"ticket": {tk}, "email": {"hosted-wait@example.com"}, "name": {"Hosted"}, "password": {"a long enough password"}})
	if joined.Status != 200 || strings.Contains(joined.Body, `name="code"`) || !strings.Contains(joined.Body, "waitlist") {
		t.Fatalf("hosted join: %d %s", joined.Status, joined.Body)
	}

	// Sign up with the token: a normal verified sign-up; completing it marks
	// the entry.
	r = signup("ada@example.com", token)
	if r.Status != 202 || r.JSON["status"] != "code_sent" {
		t.Fatalf("token sign-up: %d %s", r.Status, r.Body)
	}
	code, _ := e.Mail.Last("email_verification")
	if code.Code == "" || code.Email != "ada@example.com" {
		t.Fatalf("code mail: %+v", code)
	}
	if n := count(t, e.DB, `SELECT count(*) FROM users WHERE email='ada@example.com'`); n != 0 {
		t.Fatal("account exists before verification")
	}
	done := e.Must("POST", "/identity/v1/signup/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": r.JSON["challenge_id"], "code": code.Code}, 201).JSON
	user, _ := done["user_id"].(string)
	if user == "" {
		t.Fatalf("signed up: %v", done)
	}
	got := e.Must("GET", base+"/"+id, e.Owner, nil, 200).JSON
	if got["status"] != "completed" || got["completed_user_id"] != user {
		t.Fatalf("after completion: %v", got)
	}
	// The token is spent: it no longer prefills, and the entry cannot be
	// approved again.
	if bad = b.get("/hosted/signup?ticket=" + url.QueryEscape(tk) + "&waitlist=" + url.QueryEscape(token)); strings.Contains(bad.Body, "ada@example.com") {
		t.Fatal("a completed token prefilled")
	}
	e.Must("POST", base+"/"+id+"/approve", e.Owner, nil, 409)
	if e.Do("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "ada@example.com", "name": "Ada", "password": "a long enough password", "waitlist_token": token}).JSON["status"] != "waitlisted" {
		t.Fatal("a spent token unlocked another sign-up")
	}

	// Auto-approved domains skip the list.
	waitlistEnv(e, fiber.Map{"waitlist_auto_approve_domains": []string{"vip.example"}})
	if r = signup("boss@vip.example", ""); r.Status != 202 || r.JSON["status"] != "code_sent" {
		t.Fatalf("auto-approve: %d %s", r.Status, r.Body)
	}
	// Bad settings.
	e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, fiber.Map{"allow_password": true, "allow_email_code": true, "allow_signup": true, "signup_organization_id": e.Org, "waitlist": true, "waitlist_signup_url": "http://app.example.com/signup"}, 400)
	e.Must("PUT", e.Base+"/sign-in-policy", e.Owner, fiber.Map{"allow_password": true, "allow_email_code": true, "allow_signup": true, "signup_organization_id": e.Org, "waitlist": true, "waitlist_auto_approve_domains": []string{"not a domain"}}, 400)
	// Events of this journey: the address never appears in joined; the
	// completion is recorded.
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='waitlist.joined' AND data ? 'email_domain' AND NOT (data::text LIKE '%@%') AND actor_kind='system'`, e.EnvID); n < 1 {
		t.Fatal("waitlist.joined missing or leaks the address")
	}
	for _, typ := range []string{"waitlist.approved", "waitlist.completed"} {
		if n := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type=$2`, e.EnvID, typ); n < 1 {
			t.Fatalf("no %s event", typ)
		}
	}
	// An existing account never gets an entry.
	if n := count(t, e.DB, `SELECT count(*) FROM waitlist_entries WHERE environment_id=$1 AND email=$2`, e.EnvID, e.AliceEmail); n != 0 {
		t.Fatal("an existing account got an entry")
	}
}

// TestWaitlistDecisions: reject (silent / notify), delete frees the address,
// bulk approval, and the decision events.
func TestWaitlistDecisions(t *testing.T) {
	e := newEnv(t)
	base := e.Base + "/waitlist"
	waitlistEnv(e, nil)
	signup := func(email string) Response {
		return e.Do("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": email, "name": "Wait Person", "password": "a long enough password"})
	}
	entries := func(query string) []any {
		return e.Must("GET", base+query, e.Owner, nil, 200).JSON["items"].([]any)
	}
	var r Response
	id := "00000000-0000-4000-8000-000000000000"

	// Reject: silent by default, an email with notify; a rejected address
	// stays blocked until deleted.
	for _, email := range []string{"quiet@example.com", "loud@example.com", "later@example.com"} {
		if r = signup(email); r.JSON["status"] != "waitlisted" {
			t.Fatalf("join %s: %d %s", email, r.Status, r.Body)
		}
	}
	e.Server.WaitDeliveries(5 * 1e9)
	idOf := func(email string) string {
		items := entries("?email=" + url.QueryEscape(email))
		if len(items) != 1 {
			t.Fatalf("entry %s: %v", email, items)
		}
		return items[0].(map[string]any)["id"].(string)
	}
	rejected := e.waitlistMail("waitlist_rejected")
	quiet := e.Must("POST", base+"/"+idOf("quiet@example.com")+"/reject", e.Owner, nil, 200).JSON
	if quiet["status"] != "rejected" {
		t.Fatalf("reject: %v", quiet)
	}
	e.Server.WaitDeliveries(5 * 1e9)
	if e.waitlistMail("waitlist_rejected") != rejected {
		t.Fatal("a silent reject sent mail")
	}
	e.Must("POST", base+"/"+idOf("loud@example.com")+"/reject", e.Owner, fiber.Map{"notify": true}, 200)
	e.Server.WaitDeliveries(5 * 1e9)
	if e.waitlistMail("waitlist_rejected") != rejected+1 {
		t.Fatal("notify reject sent no mail")
	}
	e.Must("POST", base+"/"+idOf("quiet@example.com")+"/approve", e.Owner, nil, 409)
	// Re-joining while rejected: same answer, still one entry, still rejected.
	if r = signup("quiet@example.com"); r.Status != 202 || r.JSON["status"] != "waitlisted" {
		t.Fatalf("rejoin: %d %s", r.Status, r.Body)
	}
	if n := len(entries("?email=quiet@example.com&status=rejected")); n != 1 {
		t.Fatalf("rejected entry: %d", n)
	}
	e.Must("DELETE", base+"/"+idOf("quiet@example.com"), e.Owner, nil, 204)
	e.Must("DELETE", base+"/"+idOf("loud@example.com"), e.Owner, nil, 204)
	if r = signup("quiet@example.com"); r.JSON["status"] != "waitlisted" {
		t.Fatalf("join after delete: %d %s", r.Status, r.Body)
	}
	if n := len(entries("?email=quiet@example.com&status=pending")); n != 1 {
		t.Fatalf("a deleted email did not join again: %d", n)
	}

	// Bulk approval: listed ids or every pending entry; an empty or double
	// selection is a bad request.
	e.Must("POST", base+"/approve", e.Owner, fiber.Map{}, 400)
	e.Must("POST", base+"/approve", e.Owner, fiber.Map{"ids": []string{id}, "all_pending": true}, 400)
	out := e.Must("POST", base+"/approve", e.Owner, fiber.Map{"ids": []string{idOf("later@example.com"), idOf("later@example.com"), "00000000-0000-4000-8000-000000000000"}}, 200).JSON
	if out["approved"] != float64(1) || out["skipped"] != float64(1) || out["more"] != false {
		t.Fatalf("bulk ids (a repeated id counts once): %v", out)
	}
	out = e.Must("POST", base+"/approve", e.Owner, fiber.Map{"all_pending": true}, 200).JSON
	if out["approved"] != float64(1) || out["more"] != false {
		t.Fatalf("bulk all: %v", out)
	}
	e.Server.WaitDeliveries(5 * 1e9)
	if e.waitlistMail("waitlist_approved") != 2 {
		t.Fatalf("approval mails: %d", e.waitlistMail("waitlist_approved"))
	}

	// Decision events name the operator.
	for _, typ := range []string{"waitlist.approved", "waitlist.rejected", "waitlist.deleted"} {
		if n := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type=$2 AND actor_kind='operator'`, e.EnvID, typ); n < 1 {
			t.Fatalf("no operator %s event", typ)
		}
	}

	// An approval that expired unused: joining again puts the address back
	// in the pending list (else it would be stuck as approved).
	if _, err := e.DB.Exec(`UPDATE waitlist_entries SET expires_at=now()-interval '1 minute' WHERE environment_id=$1 AND email='later@example.com'`, e.EnvID); err != nil {
		t.Fatal(err)
	}
	if r = signup("later@example.com"); r.Status != 202 || r.JSON["status"] != "waitlisted" {
		t.Fatalf("rejoin after expiry: %d %s", r.Status, r.Body)
	}
	if n := len(entries("?email=later@example.com&status=pending")); n != 1 {
		t.Fatalf("expired approval not back to pending: %d", n)
	}
}

// TestWaitlistAPIPermissions: /api/v1 needs iam:waitlist:read for reads and
// iam:waitlist:write for decisions.
func TestWaitlistAPIPermissions(t *testing.T) {
	e := newEnv(t)
	waitlistEnv(e, nil)
	api := "/api/v1/environments/" + e.EnvID + "/waitlist"
	r := e.Do("POST", "/identity/v1/signup", "", fiber.Map{"environment_id": e.EnvID, "email": "api@example.com", "name": "Api", "password": "a long enough password"})
	if r.Status != 202 || r.JSON["status"] != "waitlisted" {
		t.Fatalf("join: %d %s", r.Status, r.Body)
	}
	reader, writer, stranger := e.scopedToken("iam:waitlist:read"), e.scopedToken("iam:waitlist:write"), e.scopedToken("iam:users:read")

	list := e.Must("GET", api, reader, nil, 200).JSON["items"].([]any)
	if len(list) != 1 {
		t.Fatalf("list: %v", list)
	}
	id := list[0].(map[string]any)["id"].(string)
	e.Must("GET", api+"/"+id, reader, nil, 200)
	e.Must("GET", api, stranger, nil, 403)
	e.Must("GET", api, writer, nil, 403)
	e.Must("GET", api, "", nil, 401)

	e.Must("POST", api+"/"+id+"/approve", reader, nil, 403)
	e.Must("POST", api+"/"+id+"/approve", stranger, nil, 403)
	e.Must("POST", api+"/approve", reader, fiber.Map{"all_pending": true}, 403)
	e.Must("POST", api+"/"+id+"/approve", writer, nil, 200)
	e.Must("POST", api+"/"+id+"/reject", reader, nil, 403)
	e.Must("DELETE", api+"/"+id, reader, nil, 403)
	e.Must("DELETE", api+"/"+id, writer, nil, 204)
	// The IAM resource's permissions list carries the new pair.
	if n := count(t, e.DB, `SELECT count(*) FROM resources WHERE id=$1 AND permissions @> ARRAY['iam:waitlist:read','iam:waitlist:write']`, e.IAMResource()); n != 1 {
		t.Fatal("IAM resource lacks the waitlist permissions")
	}
	// Events carry the token's subject as actor.
	if n := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='waitlist.deleted' AND actor_kind='machine' OR actor_kind='service_account'`, e.EnvID); n < 1 {
		t.Log("waitlist.deleted actor is not a service account (informational)")
	}
}
