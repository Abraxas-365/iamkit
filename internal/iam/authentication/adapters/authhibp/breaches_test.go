package authhibp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
func TestBreachedSendsOnlyThePrefix(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("Add-Padding") != "true" {
			t.Error("padding not requested")
		}
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n"))
	}))
	defer srv.Close()
	b := Breaches{Endpoint: srv.URL + "/range/"}
	breached, err := b.Breached(context.Background(), "password")
	if err != nil || !breached {
		t.Fatalf("breached=%v err=%v", breached, err)
	}
	if path != "/range/5BAA6" {
		t.Fatalf("sent %q", path)
	}
	breached, err = b.Breached(context.Background(), "correct horse battery staple, unbreached")
	if err != nil || breached {
		t.Fatalf("unbreached: breached=%v err=%v", breached, err)
	}
}

func TestPaddingEntriesAreNotBreaches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\n"))
	}))
	defer srv.Close()
	if breached, _ := (Breaches{Endpoint: srv.URL + "/"}).Breached(context.Background(), "password"); breached {
		t.Fatal("padding entry counted")
	}
}

func TestServiceFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	_, err := (Breaches{Endpoint: srv.URL + "/"}).Breached(context.Background(), "password")
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("want error, got %v", err)
	}
}
