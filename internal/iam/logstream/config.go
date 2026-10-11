package logstream

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/Abraxas-365/iamkit/internal/blob"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
)

// DatadogSites are the Datadog regions logs can be sent to
// (https://http-intake.logs.<site>/api/v2/logs).
var DatadogSites = []string{"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com", "ddog-gov.com"}

// MaxTags caps a Datadog stream's tags.
const MaxTags = 20

// Config holds a destination's non-secret settings. Each destination uses
// its own fields and refuses the others:
//
//	datadog  site, service, tags
//	splunk   url, index, source, sourcetype
//	s3       bucket, region, prefix, endpoint, path_style, access_key_id
//	https    url
type Config struct {
	// Datadog.
	Site    string   `json:"site,omitempty"`
	Service string   `json:"service,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	// Splunk and https.
	URL        string `json:"url,omitempty"`
	Index      string `json:"index,omitempty"`
	Source     string `json:"source,omitempty"`
	SourceType string `json:"sourcetype,omitempty"`
	// S3 and S3-compatible servers.
	Bucket      string `json:"bucket,omitempty"`
	Region      string `json:"region,omitempty"`
	Prefix      string `json:"prefix,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
	PathStyle   bool   `json:"path_style,omitempty"`
	AccessKeyID string `json:"access_key_id,omitempty"`
}

var (
	bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	ipLike     = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	regionName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,48}[a-z0-9]$`)
)

// Normalize trims the free-text fields.
func (c Config) Normalize() Config {
	for _, p := range []*string{&c.Site, &c.Service, &c.URL, &c.Index, &c.Source, &c.SourceType, &c.Bucket, &c.Region, &c.Prefix, &c.Endpoint, &c.AccessKeyID} {
		*p = strings.TrimSpace(*p)
	}
	c.Prefix = strings.TrimSuffix(c.Prefix, "/")
	c.URL = strings.TrimSuffix(c.URL, "/")
	c.Endpoint = strings.TrimSuffix(c.Endpoint, "/")
	tags := make([]string, 0, len(c.Tags))
	for _, t := range c.Tags {
		tags = append(tags, strings.TrimSpace(t))
	}
	c.Tags = tags
	if len(tags) == 0 {
		c.Tags = nil
	}
	return c
}

// Validate checks the config of the destination, one error per field, and
// refuses fields the destination does not use.
func (c Config) Validate(destination string) error {
	rest := c
	switch destination {
	case DestinationDatadog:
		rest.Site, rest.Service, rest.Tags = "", "", nil
		if !contains(DatadogSites, c.Site) {
			return errx.Validation("site must be one of " + strings.Join(DatadogSites, ", "))
		}
		if err := text("service", c.Service, 100, false); err != nil {
			return err
		}
		if len(c.Tags) > MaxTags {
			return errx.Validation("tags may have at most 20 entries")
		}
		for _, t := range c.Tags {
			if t == "" || len(t) > 200 || strings.ContainsAny(t, ",\n\r") || hasControl(t) {
				return errx.Validation("tags must be 1 to 200 characters without commas")
			}
		}
	case DestinationSplunk:
		rest.URL, rest.Index, rest.Source, rest.SourceType = "", "", "", ""
		if err := endpoint("url", c.URL, true); err != nil {
			return err
		}
		for _, f := range []struct{ name, v string }{{"index", c.Index}, {"source", c.Source}, {"sourcetype", c.SourceType}} {
			if err := text(f.name, f.v, 100, false); err != nil {
				return err
			}
		}
	case DestinationS3:
		rest.Bucket, rest.Region, rest.Prefix, rest.Endpoint, rest.PathStyle, rest.AccessKeyID = "", "", "", "", false, ""
		if !validBucket(c.Bucket) {
			return errx.Validation("bucket must be a valid S3 bucket name (3 to 63 lowercase letters, digits, dots and hyphens)")
		}
		if !regionName.MatchString(c.Region) {
			return errx.Validation("region is required (for example us-east-1)")
		}
		if err := validPrefix(c.Prefix); err != nil {
			return err
		}
		if c.Endpoint != "" {
			if err := endpoint("endpoint", c.Endpoint, false); err != nil {
				return err
			}
		}
		if err := text("access_key_id", c.AccessKeyID, 128, true); err != nil || strings.ContainsAny(c.AccessKeyID, " \t") {
			return errx.Validation("access_key_id is required (1 to 128 characters without spaces)")
		}
	case DestinationHTTPS:
		rest.URL = ""
		if err := endpoint("url", c.URL, true); err != nil {
			return err
		}
	default:
		return errx.Validation("destination must be datadog, splunk, s3 or https")
	}
	if !rest.empty() {
		return errx.Validation("config has fields the " + destination + " destination does not use")
	}
	return nil
}

func (c Config) empty() bool {
	return c.Site == "" && c.Service == "" && len(c.Tags) == 0 && c.URL == "" && c.Index == "" && c.Source == "" &&
		c.SourceType == "" && c.Bucket == "" && c.Region == "" && c.Prefix == "" && c.Endpoint == "" && !c.PathStyle && c.AccessKeyID == ""
}

// IntakeURL is Datadog's log intake for the site.
func (c Config) IntakeURL() string {
	return "https://http-intake.logs." + c.Site + "/api/v2/logs"
}

func validBucket(name string) bool {
	return bucketName.MatchString(name) && !ipLike.MatchString(name) && !strings.Contains(name, "..") &&
		!strings.Contains(name, ".-") && !strings.Contains(name, "-.") &&
		!strings.HasPrefix(name, "xn--") && !strings.HasSuffix(name, "-s3alias")
}

// validPrefix accepts an object key prefix: relative, no empty or dot
// segments (blob.ValidateKey), short enough that every key stays valid.
func validPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if strings.HasPrefix(prefix, "/") || len(prefix) > 512 || blob.ValidateKey(prefix) != nil || hasControl(prefix) {
		return errx.Validation("prefix must be a relative path of at most 512 characters, without a leading slash or empty segments")
	}
	return nil
}

// Redirects reports whether next sends the stored secret somewhere else
// than c does (another host, bucket, region or key id), so an edit cannot
// hand a secret its author never saw to a server of their choosing.
// Datadog sites are an allow-list and https streams sign with their own
// generated secret, so neither counts.
func (c Config) Redirects(destination string, next Config) bool {
	switch destination {
	case DestinationSplunk:
		return c.URL != next.URL
	case DestinationS3:
		return c.Endpoint != next.Endpoint || c.Bucket != next.Bucket || c.Region != next.Region ||
			c.AccessKeyID != next.AccessKeyID || c.PathStyle != next.PathStyle
	}
	return false
}

// endpoint validates an operator-supplied URL: https (http on loopback for
// development, event.ValidEndpoint), no path or query when bare.
func endpoint(field, raw string, allowPath bool) error {
	if err := event.ValidEndpoint(raw); err != nil {
		return errx.Validation(field + " must be an https URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery != "" || (!allowPath && u.Path != "" && u.Path != "/") {
		return errx.Validation(field + " must be an https URL" + map[bool]string{true: "", false: " without a path"}[allowPath])
	}
	return nil
}

func text(field, v string, max int, required bool) error {
	if required && v == "" {
		return errx.Validation(field + " is required")
	}
	if len(v) > max || hasControl(v) {
		return errx.Validation(field + " must be at most " + itoa(max) + " characters without control characters")
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }
