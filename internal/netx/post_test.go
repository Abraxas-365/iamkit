package netx

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type fixed struct{ status int }

func (f fixed) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.status, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 2*MaxErrorBody)))}, nil
}

func TestCapErrors(t *testing.T) {
	for status, want := range map[int]int{500: MaxErrorBody, 403: MaxErrorBody, 200: 2 * MaxErrorBody} {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
		res, err := CapErrors(fixed{status}).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if len(body) != want {
			t.Errorf("%d: read %d bytes, want %d", status, len(body), want)
		}
	}
}
