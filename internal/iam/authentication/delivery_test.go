package authentication

import (
	"encoding/json"
	"testing"
)

// Challenge payloads must stay exactly {email,purpose,code} for existing
// webhook receivers.
func TestMessageChallengePayloadUnchanged(t *testing.T) {
	raw, err := json.Marshal(Message{Email: "a@b.example", Purpose: "login", Code: "12345678"})
	if err != nil || string(raw) != `{"email":"a@b.example","purpose":"login","code":"12345678"}` {
		t.Fatalf("payload = %s %v", raw, err)
	}
}

func TestInvitationLink(t *testing.T) {
	if got := InvitationLink("https://app.example/join?ref=x", "ik_inv_a+b"); got != "https://app.example/join?ref=x&token=ik_inv_a%2Bb" {
		t.Errorf("link = %s", got)
	}
	if got := InvitationLink("", "t"); got != "" {
		t.Errorf("empty base = %s", got)
	}
}

func TestDeliveryConfigInvitationURL(t *testing.T) {
	ok := DeliveryConfigInput{WebhookURL: "https://mail.example", WebhookToken: "t"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"ftp://x.example", "http://app.example/join", "https://app.example/#frag"} {
		in := ok
		in.InvitationURL = bad
		if in.Validate() == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
