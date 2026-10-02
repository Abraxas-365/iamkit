package oauth

import (
	"slices"
	"testing"
)

func TestOrigins(t *testing.T) {
	got, err := Origins([]string{"https://App.Example.com", "https://app.example.com:443/", "http://localhost:3000", "https://app.example.com:8443"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://app.example.com", "http://localhost:3000", "https://app.example.com:8443"}
	if !slices.Equal(got, want) {
		t.Fatalf("Origins = %v, want %v", got, want)
	}
	for _, bad := range []string{"http://app.example.com", "https://app.example.com/login", "https://*.example.com", "https://u:p@app.example.com", "app.example.com", "ftp://app.example.com", "https://app.example.com?x=1", ""} {
		if _, err := Origins([]string{bad}); err == nil {
			t.Errorf("Origins accepted %q", bad)
		}
	}
	if out, err := Origins(nil); out != nil || err != nil {
		t.Fatalf("Origins(nil) = %v, %v", out, err)
	}
	many := make([]string, MaxOrigins+1)
	for i := range many {
		many[i] = "https://a.example"
	}
	if _, err := Origins(many); err == nil {
		t.Fatal("Origins accepted too many origins")
	}
}
