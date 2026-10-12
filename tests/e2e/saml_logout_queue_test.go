package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlpg"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml/samltest"
	"github.com/gofiber/fiber/v2"
)

// TestSAMLLogoutQueue covers the outbox against a real database: a session
// that reached an application with a back-channel URL queues one
// notification when it ends (revoked or deleted), an application with only
// slo_url queues nothing, ended sessions queue nothing twice, the
// repository claims and settles rows, and pruning drops finished ones.
func TestSAMLLogoutQueue(t *testing.T) {
	e := newEnv(t)
	base := e.Base + "/saml/service-providers"
	soapSP := samltest.New("https://soap.example.com/saml", "https://soap.example.com/acs")
	redirectSP := samltest.New("https://redirect.example.com/saml", "https://redirect.example.com/acs")
	create := func(sp *samltest.SP, entity string, extra fiber.Map) string {
		body := fiber.Map{"name": entity, "application_id": e.Client, "resource_id": e.Res, "entity_id": entity, "acs_urls": []string{entity + "/acs"}, "certificate": sp.Certificate()}
		for k, v := range extra {
			body[k] = v
		}
		return e.ID("POST", base, body)
	}
	soapID := create(soapSP, "https://soap.example.com/saml", fiber.Map{"slo_soap_url": "https://soap.example.com/soap"})
	redirectID := create(redirectSP, "https://redirect.example.com/saml", fiber.Map{"slo_url": "https://redirect.example.com/slo"})

	e.Login(e.AliceEmail)
	session := func() string {
		t.Helper()
		var id string
		if err := e.DB.Get(&id, `SELECT id FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND parent_session_id IS NULL ORDER BY created_at DESC LIMIT 1`, e.Alice); err != nil {
			t.Fatal(err)
		}
		return id
	}
	link := func(session, provider string) {
		t.Helper()
		e.DB.MustExec(`INSERT INTO saml_idp_sessions (session_id, service_provider_id, environment_id, name_id) VALUES ($1,$2,$3,$4)`, session, provider, e.EnvID, e.AliceEmail)
	}
	queued := func(session string) (n int) {
		e.DB.Get(&n, `SELECT count(*) FROM saml_logout_notifications WHERE session_id=$1`, session)
		return
	}

	first := session()
	link(first, soapID)
	link(first, redirectID)
	e.Must("POST", e.Base+"/users/"+e.Alice+"/revoke-sessions", e.Owner, nil, 200)
	if n := queued(first); n != 1 {
		t.Fatalf("revoked session queued %d notifications, want 1 (only the back-channel application)", n)
	}
	var provider string
	e.DB.Get(&provider, `SELECT service_provider_id FROM saml_logout_notifications WHERE session_id=$1`, first)
	if provider != soapID {
		t.Fatalf("queued for %s, want %s", provider, soapID)
	}
	// Revoking again changes nothing.
	e.DB.MustExec(`UPDATE sessions SET revoked_at = now() WHERE id=$1`, first)
	if n := queued(first); n != 1 {
		t.Fatalf("a second revoke queued again: %d", n)
	}

	// Deleting a live session queues too.
	e.Login(e.AliceEmail)
	second := session()
	link(second, soapID)
	e.DB.MustExec(`DELETE FROM refresh_tokens WHERE session_id=$1`, second)
	e.DB.MustExec(`DELETE FROM sessions WHERE id=$1`, second)
	if n := queued(second); n != 1 {
		t.Fatalf("deleted session queued %d", n)
	}

	repo := samlpg.New(e.DB)
	ctx := context.Background()
	claimed, err := repo.ClaimLogouts(ctx, samlidp.LogoutBatch)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claimed %d: %v", len(claimed), err)
	}
	for _, n := range claimed {
		if n.ServiceProvider.ID.String() != soapID || n.ServiceProvider.SLOSOAPURL != "https://soap.example.com/soap" || n.NameID != e.AliceEmail || n.Attempts != 1 || n.Environment.String() != e.EnvID {
			t.Fatalf("claimed %+v", n)
		}
	}
	// Leased rows are not claimed again.
	if again, err := repo.ClaimLogouts(ctx, samlidp.LogoutBatch); err != nil || len(again) != 0 {
		t.Fatalf("claimed twice: %d %v", len(again), err)
	}
	if err := repo.LogoutDelivered(ctx, claimed[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.LogoutRetry(ctx, claimed[1].ID, time.Now().Add(-time.Second), "timeout"); err != nil {
		t.Fatal(err)
	}
	retried, err := repo.ClaimLogouts(ctx, samlidp.LogoutBatch)
	if err != nil || len(retried) != 1 || retried[0].ID != claimed[1].ID || retried[0].Attempts != 2 {
		t.Fatalf("retry: %+v %v", retried, err)
	}
	if err := repo.LogoutFailed(ctx, retried[0], "gave up"); err != nil {
		t.Fatal(err)
	}
	var failed int
	e.DB.Get(&failed, `SELECT count(*) FROM saml_logout_notifications WHERE failed_at IS NOT NULL AND last_error='gave up'`)
	if failed != 1 {
		t.Fatalf("failed rows = %d", failed)
	}

	// Pruning keeps recent rows and drops finished old ones and the links
	// of ended sessions.
	if err := repo.PruneLogouts(ctx, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var rows int
	e.DB.Get(&rows, `SELECT count(*) FROM saml_logout_notifications`)
	if rows != 2 {
		t.Fatalf("recent rows pruned: %d", rows)
	}
	e.DB.MustExec(`UPDATE saml_idp_sessions SET created_at = now() - interval '2 hours'`)
	if err := repo.PruneLogouts(ctx, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	e.DB.Get(&rows, `SELECT count(*) FROM saml_logout_notifications`)
	var links int
	e.DB.Get(&links, `SELECT count(*) FROM saml_idp_sessions`)
	if rows != 0 || links != 0 {
		t.Fatalf("after pruning: %d notifications, %d links", rows, links)
	}
}
