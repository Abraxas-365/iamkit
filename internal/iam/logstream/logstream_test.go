package logstream_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestConfigValidate(t *testing.T) {
	good := map[string]logstream.Config{
		logstream.DestinationDatadog: {Site: "datadoghq.eu", Service: "iam", Tags: []string{"env:prod"}},
		logstream.DestinationSplunk:  {URL: "https://splunk.example.com:8088", Index: "main"},
		logstream.DestinationS3:      {Bucket: "my-logs", Region: "us-east-1", Prefix: "iam/prod", AccessKeyID: "AKIA"},
		logstream.DestinationHTTPS:   {URL: "https://example.com/hook"},
	}
	for dest, c := range good {
		if err := c.Validate(dest); err != nil {
			t.Errorf("%s: %v", dest, err)
		}
	}
	tags := make([]string, 21)
	for i := range tags {
		tags[i] = "a:b"
	}
	bad := []struct {
		name string
		dest string
		c    logstream.Config
	}{
		{"datadog site", logstream.DestinationDatadog, logstream.Config{Site: "evil.com"}},
		{"datadog tags", logstream.DestinationDatadog, logstream.Config{Site: "datadoghq.com", Tags: tags}},
		{"datadog comma tag", logstream.DestinationDatadog, logstream.Config{Site: "datadoghq.com", Tags: []string{"a,b"}}},
		{"datadog foreign field", logstream.DestinationDatadog, logstream.Config{Site: "datadoghq.com", Bucket: "x"}},
		{"splunk http", logstream.DestinationSplunk, logstream.Config{URL: "http://splunk.example.com"}},
		{"splunk empty", logstream.DestinationSplunk, logstream.Config{}},
		{"s3 bucket upper", logstream.DestinationS3, logstream.Config{Bucket: "My_Bucket", Region: "us-east-1", AccessKeyID: "a"}},
		{"s3 bucket ip", logstream.DestinationS3, logstream.Config{Bucket: "192.168.1.1", Region: "us-east-1", AccessKeyID: "a"}},
		{"s3 region", logstream.DestinationS3, logstream.Config{Bucket: "bucket", AccessKeyID: "a"}},
		{"s3 prefix slash", logstream.DestinationS3, logstream.Config{Bucket: "bucket", Region: "us-east-1", Prefix: "/x", AccessKeyID: "a"}},
		{"s3 prefix dotdot", logstream.DestinationS3, logstream.Config{Bucket: "bucket", Region: "us-east-1", Prefix: "a/../b", AccessKeyID: "a"}},
		{"s3 endpoint http", logstream.DestinationS3, logstream.Config{Bucket: "bucket", Region: "us-east-1", Endpoint: "http://minio.example.com", AccessKeyID: "a"}},
		{"s3 endpoint path", logstream.DestinationS3, logstream.Config{Bucket: "bucket", Region: "us-east-1", Endpoint: "https://minio.example.com/x", AccessKeyID: "a"}},
		{"s3 no access key", logstream.DestinationS3, logstream.Config{Bucket: "bucket", Region: "us-east-1"}},
		{"https http", logstream.DestinationHTTPS, logstream.Config{URL: "http://example.com"}},
		{"https foreign", logstream.DestinationHTTPS, logstream.Config{URL: "https://example.com", Index: "x"}},
		{"unknown", "kafka", logstream.Config{}},
	}
	for _, tc := range bad {
		if err := tc.c.Validate(tc.dest); err == nil {
			t.Errorf("%s: want error", tc.name)
		}
	}
}

func TestConfigRedirects(t *testing.T) {
	s3 := logstream.Config{Bucket: "my-logs", Region: "us-east-1", AccessKeyID: "AKIA"}
	moved := s3
	moved.Endpoint = "https://storage.example.com"
	renamed := s3
	renamed.Prefix = "iam"
	splunk := logstream.Config{URL: "https://splunk.example.com:8088"}
	for name, c := range map[string]struct {
		dest     string
		from, to logstream.Config
		want     bool
	}{
		"s3 endpoint":  {logstream.DestinationS3, s3, moved, true},
		"s3 prefix":    {logstream.DestinationS3, s3, renamed, false},
		"splunk url":   {logstream.DestinationSplunk, splunk, logstream.Config{URL: "https://other.example.com"}, true},
		"splunk index": {logstream.DestinationSplunk, splunk, logstream.Config{URL: splunk.URL, Index: "x"}, false},
		"datadog site": {logstream.DestinationDatadog, logstream.Config{Site: "datadoghq.com"}, logstream.Config{Site: "datadoghq.eu"}, false},
		"https url":    {logstream.DestinationHTTPS, logstream.Config{URL: "https://a.example.com"}, logstream.Config{URL: "https://b.example.com"}, false},
	} {
		if got := c.from.Redirects(c.dest, c.to); got != c.want {
			t.Errorf("%s: Redirects = %v", name, got)
		}
	}
}

func TestCreateValidate(t *testing.T) {
	ok := logstream.Create{Name: "x", Destination: "datadog", Config: logstream.Config{Site: "datadoghq.com"}, Secret: "key"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]logstream.Create{
		"no name":      {Destination: "datadog", Config: ok.Config, Secret: "key"},
		"no secret":    {Name: "x", Destination: "datadog", Config: ok.Config},
		"space secret": {Name: "x", Destination: "datadog", Config: ok.Config, Secret: "a b"},
		"https secret": {Name: "x", Destination: "https", Config: logstream.Config{URL: "https://e.com"}, Secret: "s"},
	} {
		if c.Validate() == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestCheckSources(t *testing.T) {
	cases := []struct {
		sources []string
		org     bool
		ok      bool
	}{
		{[]string{"events"}, false, true},
		{[]string{"events", "audit_logs"}, false, true},
		{[]string{"audit_logs"}, true, true},
		{[]string{"events"}, true, false},
		{[]string{"events", "audit_logs"}, true, false},
		{nil, false, false},
		{[]string{"audit_logs", "audit_logs"}, false, false},
		{[]string{"other"}, false, false},
	}
	for _, c := range cases {
		if err := logstream.CheckSources(c.sources, c.org); (err == nil) != c.ok {
			t.Errorf("%v org=%v: err=%v", c.sources, c.org, err)
		}
	}
}

func TestObjectKey(t *testing.T) {
	stream := identity.NewLogStreamID()
	at := time.Date(2026, 3, 4, 9, 30, 0, 0, time.FixedZone("x", 3600))
	got := logstream.ObjectKey("iam/prod", stream, 42, at)
	want := "iam/prod/2026/03/04/08/" + stream.String() + "-42.ndjson.gz"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if got := logstream.ObjectKey("", stream, 7, at); !strings.HasPrefix(got, "2026/03/04/08/") {
		t.Fatalf("no prefix: %s", got)
	}
}

func TestPayload(t *testing.T) {
	env := identity.NewEnvironmentID()
	at := time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC)
	r := logstream.Record{Source: logstream.SourceEvents, At: at, Fields: json.RawMessage(`{"id":5,"type":"user.created"}`)}
	var got map[string]any
	if err := json.Unmarshal(r.Payload(env), &got); err != nil {
		t.Fatal(err)
	}
	if got["source"] != "events" || got["environment_id"] != env.String() || got["type"] != "user.created" || got["id"] != float64(5) ||
		got["occurred_at"] != "2026-03-04T09:30:00Z" {
		t.Fatalf("payload %v", got)
	}
	empty := logstream.Record{Source: "audit_logs", At: at, Fields: json.RawMessage(`{}`)}
	if err := json.Unmarshal(empty.Payload(env), &got); err != nil {
		t.Fatal(err)
	}
}

func TestOutcome(t *testing.T) {
	if !(logstream.Outcome{}).OK() || !(logstream.Outcome{Status: 202}).OK() {
		t.Fatal("2xx and no status are ok")
	}
	if (logstream.Outcome{Status: 500}).OK() || (logstream.Outcome{Error: "x"}).OK() {
		t.Fatal("failure is not ok")
	}
	if n := len(logstream.OutcomeOf(0, strings.Repeat("é", 1000)).Error); n > logstream.MaxError+4 {
		t.Fatalf("not truncated: %d", n)
	}
}
