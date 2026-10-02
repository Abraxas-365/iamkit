package usage_test

import (
	"net/http"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
)

func TestParseDeployment(t *testing.T) {
	v, err := usage.ParseDeployment(" users_max = 10 , emails_per_day=0,")
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := v.Max(usage.LimitUsers); !ok || n != 10 {
		t.Fatalf("users_max = %d %v", n, ok)
	}
	if n, ok := v.Max(usage.LimitEmails); !ok || n != 0 {
		t.Fatalf("emails_per_day = %d %v", n, ok)
	}
	if _, ok := v.Max(usage.LimitSMS); ok {
		t.Fatal("sms_per_day limited")
	}
	for _, bad := range []string{"users_max", "users_max=x", "nope=1", "users_max=-1", "users_max=1000000000001"} {
		if _, err := usage.ParseDeployment(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if v, err := usage.ParseDeployment(""); err != nil || len(v) != 0 {
		t.Fatalf("empty = %v %v", v, err)
	}
}

func TestTighten(t *testing.T) {
	deployment := usage.Values{usage.LimitUsers: 100, usage.LimitEmails: 50}
	got := deployment.Tighten(usage.Values{usage.LimitUsers: 500, usage.LimitEmails: 10, usage.LimitSMS: 5})
	want := usage.Values{usage.LimitUsers: 100, usage.LimitEmails: 10, usage.LimitSMS: 5}
	if len(got) != len(want) {
		t.Fatalf("tighten = %v", got)
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("tighten = %v", got)
		}
	}
	if len(deployment) != 2 || deployment[usage.LimitUsers] != 100 {
		t.Fatalf("receiver changed: %v", deployment)
	}
}

func TestErrExceeded(t *testing.T) {
	total, _ := usage.Find(usage.LimitUsers)
	rate, _ := usage.Find(usage.LimitRequests)
	for limit, status := range map[usage.Limit]int{total: http.StatusUnprocessableEntity, rate: http.StatusTooManyRequests} {
		err := usage.ErrExceeded(limit, 3)
		var e *errx.Error
		if !errx.As(err, &e) || e.HTTPStatus != status || e.Code != "QUOTA_EXCEEDED" || !e.Public || !usage.Exceeded(err) {
			t.Fatalf("%s: %#v", limit.Name, err)
		}
	}
}
