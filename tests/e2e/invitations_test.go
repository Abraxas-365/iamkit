package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestInvitationsJourney covers invite → webhook → preview → accept for a new
// and an existing account, token reuse, resend, revoke, expiry, validation,
// the invitation link and SSO-enforced organizations.
func TestInvitationsJourney(t *testing.T) {
	e := newEnv(t)
	invitations := e.Base + "/organizations/" + e.Org + "/invitations"
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	writers := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Writers"})
	writer := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "writer", "resource_id": e.Res, "permissions": []string{"invoices:write"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": writer, "organization_id": e.Org, "group_id": writers}, 204)

	// Validation: email, unknown roles/groups, active members.
	e.Must("POST", invitations, e.Owner, fiber.Map{"email": "not-an-email"}, 400)
	e.Must("POST", invitations, e.Owner, fiber.Map{"email": "bob@example.com", "role_ids": []string{"00000000-0000-4000-8000-000000000000"}}, 422)
	e.Must("POST", invitations, e.Owner, fiber.Map{"email": "bob@example.com", "group_ids": []string{"00000000-0000-4000-8000-000000000000"}}, 422)
	e.Must("POST", invitations, e.Owner, fiber.Map{"email": e.AliceEmail}, 409)

	// Invite: token shown once, webhook gets the invitation (no link: the
	// environment has no invitation page).
	inv := e.Must("POST", invitations, e.Owner, fiber.Map{"email": " Bob@Example.com ", "role_ids": []string{reader, reader}, "group_ids": []string{writers}}, 201).JSON
	token, _ := inv["token"].(string)
	if !strings.HasPrefix(token, "ik_inv_") || inv["email"] != "bob@example.com" || inv["status"] != "pending" || inv["delivery"] != "sent" || inv["link"] != nil ||
		len(inv["role_ids"].([]any)) != 1 || len(inv["group_ids"].([]any)) != 1 {
		t.Fatalf("invite = %s", mustJSON(inv))
	}
	id := inv["id"].(string)
	mail, ok := e.Mail.Last("invitation")
	if !ok || mail.Email != "bob@example.com" || mail.Token != token || mail.Organization != "Acme" || mail.Inviter != "owner@example.com" || mail.Link != "" || mail.Code != "" || mail.ExpiresAt == nil {
		t.Fatalf("mail = %+v", mail)
	}
	var stored []byte
	if err := e.DB.Get(&stored, `SELECT token_hash FROM invitations WHERE id=$1`, id); err != nil || strings.Contains(string(stored), token) {
		t.Fatalf("stored token: %v", err)
	}
	found := e.Must("GET", invitations+"/"+id, e.Owner, nil, 200)
	if strings.Contains(found.Body, "ik_inv_") || found.JSON["inviter"] == "" {
		t.Fatalf("find leaks token or lacks inviter: %s", found.Body)
	}
	e.Must("POST", invitations, e.Owner, fiber.Map{"email": "bob@example.com"}, 409)

	// Preview: masked email, password needed for a new account.
	e.Must("POST", "/identity/v1/invitations/preview", "", fiber.Map{"token": "ik_inv_unknown"}, 401)
	e.Must("POST", "/identity/v1/invitations/preview", "", fiber.Map{"token": "nope"}, 401)
	p := e.Must("POST", "/identity/v1/invitations/preview", "", fiber.Map{"token": token}, 200).JSON
	if p["email"] != "b***@example.com" || p["organization_name"] != "Acme" || p["password_required"] != true || p["sso_required"] != false {
		t.Fatalf("preview = %v", p)
	}

	// Accept: a new account needs a password; it gets the roles and groups.
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": token}, 400)
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": token, "password": "short"}, 400)
	acc := e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": token, "name": "Bob", "password": e.Pass}, 200).JSON
	if acc["email"] != "bob@example.com" || acc["organization_id"] != e.Org || acc["created"] != true || acc["user_id"] == "" {
		t.Fatalf("accept = %v", acc)
	}
	if got := e.permissions(e.Login("bob@example.com")); !equal(got, []string{"invoices:read", "invoices:write"}) {
		t.Fatalf("bob permissions = %v", got)
	}
	var verified bool
	if err := e.DB.Get(&verified, `SELECT email_verified FROM users WHERE id=$1 AND name='Bob'`, acc["user_id"]); err != nil || !verified {
		t.Fatalf("bob verified: %v %v", verified, err)
	}
	// Reuse, preview after use, revoke/resend after accept.
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": token, "password": e.Pass}, 401)
	e.Must("POST", "/identity/v1/invitations/preview", "", fiber.Map{"token": token}, 401)
	e.Must("DELETE", invitations+"/"+id, e.Owner, nil, 422)
	e.Must("POST", invitations+"/"+id+"/resend", e.Owner, nil, 422)
	if s := e.Must("GET", invitations+"/"+id, e.Owner, nil, 200).JSON; s["status"] != "accepted" || s["accepted_user_id"] != acc["user_id"] {
		t.Fatalf("accepted = %v", s)
	}

	// Existing account in another organization: joins without a password
	// change; an inactive membership is reactivated.
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	otherInv := e.Base + "/organizations/" + other + "/invitations"
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"webhook_url": "https://mail.example/hook", "webhook_token": "t", "invitation_url": "ftp://bad"}, 400)
	carol := e.User("Carol", "carol@example.com")
	e.Join(other, carol)
	e.Must("DELETE", e.Base+"/organizations/"+other+"/members/"+carol, e.Owner, nil, 204) // deactivates
	c := e.Must("POST", otherInv, e.Owner, fiber.Map{"email": "carol@example.com"}, 201).JSON
	if p := e.Must("POST", "/identity/v1/invitations/preview", "", fiber.Map{"token": c["token"]}, 200).JSON; p["password_required"] != false {
		t.Fatalf("existing preview = %v", p)
	}
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": c["token"], "password": "another long password"}, 400)
	if a := e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": c["token"]}, 200).JSON; a["created"] != false || a["user_id"] != carol {
		t.Fatalf("existing accept = %v", a)
	}
	var active bool
	if err := e.DB.Get(&active, `SELECT active FROM memberships WHERE organization_id=$1 AND user_id=$2`, other, carol); err != nil || !active {
		t.Fatalf("membership reactivated: %v %v", active, err)
	}
	// Her password is unchanged.
	e.Grant(other, carol, e.Res, "invoices:read")
	login := e.LoginBody("carol@example.com", e.Pass)
	login["organization_id"] = other
	e.Must("POST", "/identity/v1/login", "", login, 200)

	// Resend rotates the token; revoke kills it.
	d := e.Must("POST", invitations, e.Owner, fiber.Map{"email": "dave@example.com"}, 201).JSON
	r := e.Must("POST", invitations+"/"+d["id"].(string)+"/resend", e.Owner, nil, 200).JSON
	if r["token"] == d["token"] || r["delivery"] != "sent" {
		t.Fatalf("resend = %v", r)
	}
	e.Must("POST", "/identity/v1/invitations/preview", "", fiber.Map{"token": d["token"]}, 401)
	e.Must("DELETE", invitations+"/"+d["id"].(string), e.Owner, nil, 204)
	e.Must("DELETE", invitations+"/"+d["id"].(string), e.Owner, nil, 204)
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": r["token"], "password": e.Pass}, 401)
	e.Must("POST", invitations+"/"+d["id"].(string)+"/resend", e.Owner, nil, 422)
	// After revoking, a new invitation for the same email is allowed.
	e.Must("POST", invitations, e.Owner, fiber.Map{"email": "dave@example.com"}, 201)

	// Expired invitations: rejected, listed as expired, replaced on re-invite.
	x := e.Must("POST", invitations, e.Owner, fiber.Map{"email": "erin@example.com"}, 201).JSON
	if _, err := e.DB.Exec(`UPDATE invitations SET expires_at=now()-interval '1 second' WHERE id=$1`, x["id"]); err != nil {
		t.Fatal(err)
	}
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": x["token"], "password": e.Pass}, 401)
	if l := items(e.Must("GET", invitations+"?status=expired", e.Owner, nil, 200)); len(l) != 1 || l[0]["id"] != x["id"] || l[0]["status"] != "expired" {
		t.Fatalf("expired list = %v", l)
	}
	e.Must("GET", invitations+"?status=bogus", e.Owner, nil, 400)
	e.Must("POST", invitations, e.Owner, fiber.Map{"email": "erin@example.com"}, 201)
	if l := items(e.Must("GET", invitations+"?status=pending&search=erin", e.Owner, nil, 200)); len(l) != 1 {
		t.Fatalf("pending erin = %v", l)
	}
	if s := e.Must("GET", invitations+"/"+x["id"].(string), e.Owner, nil, 200).JSON; s["status"] != "revoked" {
		t.Fatalf("expired replaced = %v", s)
	}

	// Invitation page: the webhook and the response carry the link.
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"webhook_url": "http://127.0.0.1:1/hook", "webhook_token": "t", "invitation_url": "https://app.example/join?ref=mail"}, 204)
	if cfg := e.Must("GET", e.Base+"/delivery", e.Owner, nil, 200).JSON; cfg["invitation_url"] != "https://app.example/join?ref=mail" {
		t.Fatalf("delivery = %v", cfg)
	}
	f := e.Must("POST", invitations, e.Owner, fiber.Map{"email": "frank@example.com"}, 201).JSON
	if link, _ := f["link"].(string); !strings.HasPrefix(link, "https://app.example/join?") || !strings.Contains(link, "ref=mail") || !strings.Contains(link, "token="+f["token"].(string)) {
		t.Fatalf("link = %v", f["link"])
	}
	// The environment webhook is unreachable: the invitation stays usable.
	if f["delivery"] != "failed" {
		t.Fatalf("delivery = %v", f["delivery"])
	}
	e.Must("DELETE", e.Base+"/delivery", e.Owner, nil, 204)

	// Other organizations cannot see or act on an invitation.
	e.Must("GET", otherInv+"/"+f["id"].(string), e.Owner, nil, 404)
	e.Must("DELETE", otherInv+"/"+f["id"].(string), e.Owner, nil, 404)
	// Viewers read but cannot invite.
	viewer := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "viewer@example.com", "role": "viewer"}, 201).JSON["secret"].(string)
	e.Must("GET", invitations, viewer, nil, 200)
	e.Must("POST", invitations, viewer, fiber.Map{"email": "gina@example.com"}, 403)

	// Inactive organizations accept no invitations.
	g := e.Must("POST", otherInv, e.Owner, fiber.Map{"email": "gina@example.com"}, 201).JSON
	e.Must("PATCH", e.Base+"/organizations/"+other, e.Owner, fiber.Map{"active": false}, 204)
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": g["token"], "password": e.Pass}, 422)
	e.Must("POST", otherInv, e.Owner, fiber.Map{"email": "hank@example.com"}, 422)

	// Erasing a user removes the invitations addressed to or accepted by them.
	e.Must("DELETE", e.Base+"/users/"+acc["user_id"].(string)+"/permanent", e.Owner, nil, 204)
	var left int
	if err := e.DB.Get(&left, `SELECT count(*) FROM invitations WHERE email='bob@example.com'`); err != nil || left != 0 {
		t.Fatalf("erased invitations = %d %v", left, err)
	}
}

// TestInvitationSSOEnforced: an invitee of an organization that enforces SSO
// for their domain joins without a password and must sign in with SSO.
func TestInvitationSSOEnforced(t *testing.T) {
	e := newEnv(t)
	idp := newFakeIdP(t, e.Key, "acme-client")
	e.IdP.Set(idp.Client().Transport)
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "corp.example"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	conn := e.ID("POST", e.Base+"/federation-connections", fiber.Map{"organization_id": e.Org, "name": "Corp", "issuer": idp.URL, "client_id": "acme-client", "client_secret": "sealed-secret"})
	e.Must("PATCH", e.Base+"/federation-connections/"+conn, e.Owner, fiber.Map{"enforcement": "enforced"}, 204)
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})

	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "ivy@corp.example", "role_ids": []string{reader}}, 201).JSON
	if p := e.Must("POST", "/identity/v1/invitations/preview", "", fiber.Map{"token": inv["token"]}, 200).JSON; p["sso_required"] != true || p["password_required"] != false {
		t.Fatalf("preview = %v", p)
	}
	e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": inv["token"], "password": e.Pass}, 400)
	acc := e.Must("POST", "/identity/v1/invitations/accept", "", fiber.Map{"token": inv["token"], "name": "Ivy"}, 200).JSON
	if acc["sso_required"] != true || acc["created"] != true {
		t.Fatalf("accept = %v", acc)
	}
	// SSO signs the invitee in with the invited roles (links by email).
	r := e.sso(idp, conn, e.Org, map[string]any{"sub": "ivy-sub", "email": "ivy@corp.example", "email_verified": true})
	if r.Status != 200 || !equal(e.permissions(r.JSON["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatalf("sso ivy: %d %v", r.Status, r.JSON)
	}
}
