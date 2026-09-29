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
