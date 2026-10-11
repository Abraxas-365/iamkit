package user

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUpdatePhone(t *testing.T) {
	phone := func(v string) *string { return &v }
	u := Update{Phone: phone(" +1 (415) 555-0100 ")}.Normalize()
	if *u.Phone != "+14155550100" || u.Validate() != nil {
		t.Fatalf("normalized = %q %v", *u.Phone, u.Validate())
	}
	if u = (Update{Phone: phone("  ")}).Normalize(); *u.Phone != "" || u.Validate() != nil {
		t.Fatalf("clear = %q", *u.Phone)
	}
	if (Update{Phone: phone("555")}).Normalize().Validate() == nil {
		t.Fatal("short number accepted")
	}
	if (Update{}).Normalize().Phone != nil {
		t.Fatal("absent phone set")
	}
}

func TestAvatar(t *testing.T) {
	s := func(v string) *string { return &v }
	u := Update{AvatarURL: s(" https://cdn.example/a.png ")}.Normalize()
	if *u.AvatarURL != "https://cdn.example/a.png" || u.Validate() != nil {
		t.Fatalf("normalized = %q %v", *u.AvatarURL, u.Validate())
	}
	if u = (Update{AvatarURL: s("")}).Normalize(); u.Validate() != nil {
		t.Fatal("clearing the avatar is allowed")
	}
	if (Update{AvatarURL: s("http://cdn.example/a.png")}).Normalize().Validate() == nil {
		t.Fatal("http avatar accepted")
	}
	if (Create{Email: "a@example.com", Name: "A", AvatarURL: "javascript:x"}).Validate() == nil {
		t.Fatal("create accepted a bad avatar")
	}
}

func TestExternalID(t *testing.T) {
	s := func(v string) *string { return &v }
	u := Update{ExternalID: s(" crm-42 ")}.Normalize()
	if *u.ExternalID != "crm-42" || u.Validate() != nil {
		t.Fatalf("normalized = %q %v", *u.ExternalID, u.Validate())
	}
	if u = (Update{ExternalID: s("  ")}).Normalize(); *u.ExternalID != "" || u.Validate() != nil {
		t.Fatal("clearing the external ID is allowed")
	}
	if (Update{ExternalID: s(strings.Repeat("x", 256))}).Normalize().Validate() == nil {
		t.Fatal("a 256 character external ID was accepted")
	}
	if (Update{}).Normalize().ExternalID != nil {
		t.Fatal("absent external ID set")
	}
	if (Create{Email: "a@example.com", Name: "A", ExternalID: "a\nb"}).Validate() == nil {
		t.Fatal("create accepted a control character")
	}
	if (Filter{ExternalID: strings.Repeat("x", 256)}).Validate() == nil {
		t.Fatal("filter accepted a long external ID")
	}
}

func TestUpdateExternalIDJSON(t *testing.T) {
	for body, want := range map[string]string{`{"external_id":null}`: "", `{"external_id":"x1"}`: "x1"} {
		var u Update
		if err := json.Unmarshal([]byte(body), &u); err != nil || u.ExternalID == nil || *u.ExternalID != want {
			t.Fatalf("%s -> %v %v", body, u.ExternalID, err)
		}
	}
	var absent Update
	if err := json.Unmarshal([]byte(`{"name":"A"}`), &absent); err != nil || absent.ExternalID != nil || absent.Name == nil {
		t.Fatalf("absent = %+v %v", absent, err)
	}
}
