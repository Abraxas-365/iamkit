package user

import "testing"

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
