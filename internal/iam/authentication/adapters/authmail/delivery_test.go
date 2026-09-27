package authmail

import "testing"

func TestWebhookDeliveryValidate(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://mail.example.com/send": true,
		"http://localhost:9099/mail":    true,
		"http://127.0.0.1:9099/mail":    true,
		"http://mail.example.com/send":  false,
		"https://user:pw@mail.example":  false,
		"https://mail.example.com/#x":   false,
		"":                              false,
	} {
		if err := (WebhookDelivery{URL: url}).Validate(); (err == nil) != ok {
			t.Errorf("%q: got err=%v, want ok=%v", url, err, ok)
		}
	}
}
