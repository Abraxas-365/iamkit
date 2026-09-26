package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestOrganizationDomainsJourney(t *testing.T) {
	e := newEnv(t)
	domains := e.Base + "/organizations/" + e.Org + "/domains"

	// Claim: normalized, unverified, with the TXT record to publish.
	d := e.Must("POST", domains, e.Owner, fiber.Map{"domain": " Acme.Example. "}, 201).JSON
	id := d["id"].(string)
	record := d["verification"].(map[string]any)
	if d["domain"] != "acme.example" || d["verified"] != false || d["verified_at"] != nil ||
		record["type"] != "TXT" || record["name"] != "_iamkit-challenge.acme.example" ||
		!strings.HasPrefix(record["value"].(string), "iamkit-verification=") {
		t.Fatalf("created: %s", mustJSON(d))
	}
	if _, leaked := d["verification_token"]; leaked {
		t.Error("raw token field exposed")
	}
	idn := e.Must("POST", domains, e.Owner, fiber.Map{"domain": "bücher.example"}, 201).JSON
	if idn["domain"] != "xn--bcher-kva.example" {
		t.Errorf("IDN not punycoded: %v", idn["domain"])
	}
	for _, bad := range []string{"", "com", "co.uk", "*.acme.example", "localhost", "a@acme.example"} {
		e.Must("POST", domains, e.Owner, fiber.Map{"domain": bad}, 400)
	}

	// One organization per domain per environment, verified or not.
	e.Must("POST", domains, e.Owner, fiber.Map{"domain": "ACME.example"}, 409)
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	e.Must("POST", e.Base+"/organizations/"+other+"/domains", e.Owner, fiber.Map{"domain": "acme.example"}, 409)
	// Subdomains are separate claims.
	e.Must("POST", e.Base+"/organizations/"+other+"/domains", e.Owner, fiber.Map{"domain": "eu.acme.example"}, 201)
	// Other organizations cannot see or act on it.
	e.Must("GET", e.Base+"/organizations/"+other+"/domains/"+id, e.Owner, nil, 404)
	e.Must("POST", e.Base+"/organizations/"+other+"/domains/"+id+"/force-verify", e.Owner, nil, 404)

	// Verify without the record: 422 naming the record; DNS failure: 502.
	res := e.Must("POST", domains+"/"+id+"/verify", e.Owner, nil, 422)
	if !strings.Contains(res.Body, "_iamkit-challenge.acme.example") {
		t.Errorf("unhelpful error: %s", res.Body)
	}
	e.DNS.Publish("_iamkit-challenge.acme.example", "iamkit-verification=wrong")
	e.Must("POST", domains+"/"+id+"/verify", e.Owner, nil, 422)
	e.DNS.Fail("_iamkit-challenge.xn--bcher-kva.example")
	e.Must("POST", domains+"/"+idn["id"].(string)+"/verify", e.Owner, nil, 502)

	// Publish the record (quoted, among others) and verify.
	e.DNS.Publish("_iamkit-challenge.acme.example", "v=spf1 -all", `"`+record["value"].(string)+`"`)
	v := e.Must("POST", domains+"/"+id+"/verify", e.Owner, nil, 200).JSON
	if v["verified"] != true || v["verification_method"] != "dns" || v["verified_at"] == nil || v["verified_by"] == nil {
		t.Fatalf("verified: %s", mustJSON(v))
	}
	// Idempotent: verifying again keeps the original verification.
	again := e.Must("POST", domains+"/"+id+"/force-verify", e.Owner, nil, 200).JSON
	if again["verification_method"] != "dns" || again["verified_at"] != v["verified_at"] {
		t.Errorf("re-verify changed state: %s", mustJSON(again))
	}

	// Force-verify is audited as manual.
	f := e.Must("POST", domains+"/"+idn["id"].(string)+"/force-verify", e.Owner, nil, 200).JSON
	if f["verification_method"] != "manual" || f["verified"] != true {
		t.Errorf("force-verified: %s", mustJSON(f))
	}
	var audited int
	if err := e.DB.Get(&audited, `SELECT count(*) FROM audit_events WHERE target_id LIKE '%'||$1||'%' AND target_id LIKE '%method=manual%'`, idn["id"]); err != nil || audited != 1 {
		t.Errorf("force-verify audit: %d %v", audited, err)
	}

	// Listing is paginated and searchable.
	list := e.Must("GET", domains+"?search=acme", e.Owner, nil, 200)
	if got := items(list); len(got) != 1 || got[0]["domain"] != "acme.example" || got[0]["verified"] != true {
		t.Errorf("list: %s", list.Body)
	}
	if total := e.Must("GET", domains, e.Owner, nil, 200).JSON["page"].(map[string]any)["total"]; total != float64(2) {
		t.Errorf("total: %v", total)
	}

	// Viewers read but cannot mutate.
	viewer := e.Must("POST", "/management/v1/operators", e.Owner, fiber.Map{"email": "viewer@example.com", "role": "viewer"}, 201).JSON["secret"].(string)
	e.Must("GET", domains, viewer, nil, 200)
	e.Must("POST", domains, viewer, fiber.Map{"domain": "viewer.example"}, 403)
	e.Must("POST", domains+"/"+id+"/force-verify", viewer, nil, 403)

	// Releasing a domain frees it for another organization.
	e.Must("DELETE", domains+"/"+id, e.Owner, nil, 204)
	e.Must("DELETE", domains+"/"+id, e.Owner, nil, 404)
	e.Must("POST", e.Base+"/organizations/"+other+"/domains", e.Owner, fiber.Map{"domain": "acme.example"}, 201)
	e.Must("GET", domains+"/not-a-uuid", e.Owner, nil, 404)
}

// adopt_scope=verified_domains only adopts members whose email is on one of
// the organization's verified domains.
func TestSCIMAdoptVerifiedDomainsOnly(t *testing.T) {
	e := newEnv(t) // alice@example.com is a member of Acme
	bob := e.User("Bob", "bob@contoso.com")
	e.Join(e.Org, bob)
	s, _ := newSCIM(t, e)

	cred := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Scoped", "organization_id": e.Org, "adopt_existing_members": true, "adopt_scope": "verified_domains"}, 201).JSON
	e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Bad", "organization_id": e.Org, "adopt_scope": "everyone"}, 400)
	scoped := s.with(map[string]string{"Authorization": "Bearer " + cred["secret"].(string)})

	// No verified domain yet: behaves as if adoption were off.
	if res := scoped.do("POST", "/Users", `{"userName":"`+e.AliceEmail+`","externalId":"obj-alice"}`); res.Status != 409 {
		t.Fatalf("adopted without verified domain: %d %s", res.Status, res.Body)
	}
	// Claimed but unverified does not count.
	domains := e.Base + "/organizations/" + e.Org + "/domains"
	example := e.Must("POST", domains, e.Owner, fiber.Map{"domain": "example.com"}, 201).JSON["id"].(string)
	if res := scoped.do("POST", "/Users", `{"userName":"`+e.AliceEmail+`","externalId":"obj-alice"}`); res.Status != 409 {
		t.Fatalf("adopted with unverified domain: %d %s", res.Status, res.Body)
	}
	e.Must("POST", domains+"/"+example+"/force-verify", e.Owner, nil, 200)
	if got := scoped.must("POST", "/Users", `{"userName":"`+e.AliceEmail+`","externalId":"obj-alice"}`, 201).JSON; got["id"] != e.Alice {
		t.Fatalf("verified-domain member not adopted: %v", got)
	}
	// A member on another domain is still not adopted.
	if res := scoped.do("POST", "/Users", `{"userName":"bob@contoso.com","externalId":"obj-bob"}`); res.Status != 409 {
		t.Errorf("off-domain member adopted: %d %s", res.Status, res.Body)
	}

	// The scope is listed and can be widened on rotation.
	var scope string
	if err := e.DB.Get(&scope, `SELECT adopt_scope FROM provisioning_connections WHERE id=$1`, cred["connection_id"]); err != nil || scope != "verified_domains" {
		t.Fatalf("scope: %q %v", scope, err)
	}
	wide := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Wide", "organization_id": e.Org, "connection_id": cred["connection_id"], "adopt_scope": "any"}, 201).JSON
	widened := s.with(map[string]string{"Authorization": "Bearer " + wide["secret"].(string)})
	if got := widened.must("POST", "/Users", `{"userName":"bob@contoso.com","externalId":"obj-bob"}`, 201).JSON; got["id"] != bob {
		t.Errorf("widened scope did not adopt: %v", got)
	}
}
