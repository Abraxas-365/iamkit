package identity

import "testing"

func TestValidateIssuer(t *testing.T) {
	for _, issuer := range []string{
		"https://iam.example", "https://iam.example/tenant",
		"http://localhost", "http://localhost:18998", "http://127.0.0.1:18998",
		"http://[::1]:18998", "http://LOCALHOST:18998",
	} {
		t.Run(issuer, func(t *testing.T) {
			if err := ValidateIssuer(issuer); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, issuer := range []string{
		"", "localhost:18998", "https://", "http://", "//localhost:18998",
		"http://iam.example", "http://192.168.1.10:18998", "http://0.0.0.0:18998",
		"http://localhost.example", "http://127.0.0.1.example", "http://localhost@evil.example",
		"http://evil.example@localhost", "https://user:password@iam.example",
		"http://localhost?query=value", "https://iam.example?", "https://iam.example#fragment",
		"ftp://localhost", "http://localhost:bad", "http://[::1",
	} {
		t.Run(issuer, func(t *testing.T) {
			if err := ValidateIssuer(issuer); err == nil {
				t.Fatal("invalid issuer accepted")
			}
		})
	}
}
