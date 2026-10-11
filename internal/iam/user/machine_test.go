package user

import (
	"testing"
)

func TestCreateMachine(t *testing.T) {
	ok := Create{Kind: KindMachine, Name: "Invoice sync"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("machine user refused: %v", err)
	}
	for name, c := range map[string]Create{
		"email":    {Kind: KindMachine, Name: "bot", Email: "bot@example.com"},
		"password": {Kind: KindMachine, Name: "bot", Password: "correct horse battery"},
		"username": {Kind: KindMachine, Name: "bot", Username: "bot"},
		"otp":      {Kind: KindMachine, Name: "bot", OTPEnabled: true},
		"kind":     {Kind: "robot", Name: "bot"},
		"name":     {Kind: KindMachine},
	} {
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if (Filter{Kind: "robot"}).Validate() == nil {
		t.Error("unknown filter kind accepted")
	}
	if (Filter{Kind: KindMachine}).Validate() != nil {
		t.Error("machine filter refused")
	}
}
