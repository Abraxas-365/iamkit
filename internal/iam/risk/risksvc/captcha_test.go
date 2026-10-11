package risksvc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type fakeCaptchaRepo struct {
	cfg    *risk.CaptchaConfig
	sealed string
	passes map[string]time.Time
	uses   map[string]int
	err    error
	audits []string
}

func (f *fakeCaptchaRepo) Captcha(_ context.Context, _ identity.EnvironmentID) (risk.CaptchaConfig, string, error) {
	if f.err != nil {
		return risk.CaptchaConfig{}, "", f.err
	}
	if f.cfg == nil {
		return risk.CaptchaConfig{}, "", errx.NotFound("no CAPTCHA")
	}
	return *f.cfg, f.sealed, nil
}
func (f *fakeCaptchaRepo) SaveCaptcha(_ context.Context, m risk.Mutation, c risk.CaptchaConfig, sealed string) error {
	f.cfg, f.sealed = &c, sealed
	f.audits = append(f.audits, m.Action)
	return nil
}
func (f *fakeCaptchaRepo) DeleteCaptcha(_ context.Context, m risk.Mutation) error {
	f.cfg = nil
	f.audits = append(f.audits, m.Action)
	return nil
}
func (f *fakeCaptchaRepo) SavePass(_ context.Context, _ identity.EnvironmentID, ticket []byte, expires time.Time, uses int) error {
	if f.passes == nil {
		f.passes, f.uses = map[string]time.Time{}, map[string]int{}
	}
	f.passes[string(ticket)], f.uses[string(ticket)] = expires, uses
	return nil
}
func (f *fakeCaptchaRepo) Pass(_ context.Context, _ identity.EnvironmentID, ticket []byte, now time.Time) (bool, error) {
	exp, ok := f.passes[string(ticket)]
	return ok && exp.After(now) && f.uses[string(ticket)] > 0, nil
}
func (f *fakeCaptchaRepo) UsePass(ctx context.Context, env identity.EnvironmentID, ticket []byte, now time.Time) (bool, error) {
	if ok, _ := f.Pass(ctx, env, ticket, now); !ok {
		return false, nil
	}
	f.uses[string(ticket)]--
	return true, nil
}

type fakeSiteverify struct {
	answer risk.Answer
	err    error
	secret string
	check  risk.CaptchaCheck
	calls  int
}

func (f *fakeSiteverify) Verify(_ context.Context, _ string, secret string, check risk.CaptchaCheck) (risk.Answer, error) {
	f.calls++
	f.secret, f.check = secret, check
	return f.answer, f.err
}

type captchaCipher struct{}

func (captchaCipher) Seal(p []byte) (string, error) { return "sealed:" + string(p), nil }
func (captchaCipher) Open(s string) ([]byte, error) {
	return []byte(strings.TrimPrefix(s, "sealed:")), nil
}

type captchaFlags map[string]bool

func (f captchaFlags) Enabled(_ context.Context, _ identity.EnvironmentID, name string) (bool, error) {
	return f[name], nil
}

func newCaptchaService(t *testing.T, repo *fakeCaptchaRepo, v *fakeSiteverify, features risk.Features) *Service {
	t.Helper()
	return New(Deps{Captchas: repo, Verifier: v, Cipher: captchaCipher{}, Features: features, IssuerHost: "auth.example.com"})
}

var captchaEnv = identity.NewEnvironmentID()

func configuredCaptcha() *fakeCaptchaRepo {
	return &fakeCaptchaRepo{cfg: &risk.CaptchaConfig{Environment: captchaEnv, Provider: risk.ProviderTurnstile, SiteKey: "site", Hosted: true, Headless: true}, sealed: "sealed:secret"}
}

func errCode(err error) string {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestCheckCaptchaWithoutConfigIsNoop(t *testing.T) {
	v := &fakeSiteverify{}
	s := newCaptchaService(t, &fakeCaptchaRepo{}, v, captchaFlags{config.FeatureCaptcha: true})
	out, err := s.CheckCaptcha(context.Background(), risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHeadless})
	if out != "" || err != nil || v.calls != 0 {
		t.Fatalf("out=%q err=%v calls=%d", out, err, v.calls)
	}
}

func TestCheckCaptchaFeatureOffSkips(t *testing.T) {
	v := &fakeSiteverify{}
	s := newCaptchaService(t, configuredCaptcha(), v, captchaFlags{config.FeatureCaptcha: false})
	out, err := s.CheckCaptcha(context.Background(), risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHeadless})
	if out != "" || err != nil || v.calls != 0 {
		t.Fatalf("out=%q err=%v calls=%d", out, err, v.calls)
	}
	if pub, _ := s.PublicCaptcha(context.Background(), captchaEnv, risk.SurfaceHeadless); pub.Enabled {
		t.Fatal("public captcha enabled with the feature off")
	}
}

func TestCheckCaptchaSurfaceSwitch(t *testing.T) {
	repo := configuredCaptcha()
	repo.cfg.Headless = false
	v := &fakeSiteverify{}
	s := newCaptchaService(t, repo, v, captchaFlags{config.FeatureCaptcha: true})
	if out, err := s.CheckCaptcha(context.Background(), risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHeadless}); out != "" || err != nil {
		t.Fatalf("headless off: out=%q err=%v", out, err)
	}
	if _, err := s.CheckCaptcha(context.Background(), risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHosted}); errCode(err) != risk.CodeCaptchaRequired {
		t.Fatalf("hosted on, no token: %v", err)
	}
}

func TestCheckCaptchaMissingToken(t *testing.T) {
	v := &fakeSiteverify{}
	s := newCaptchaService(t, configuredCaptcha(), v, captchaFlags{config.FeatureCaptcha: true})
	_, err := s.CheckCaptcha(context.Background(), risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHeadless, Token: "  "})
	if errCode(err) != risk.CodeCaptchaRequired || v.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, v.calls)
	}
	_, err = s.CheckCaptcha(context.Background(), risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHeadless, Token: strings.Repeat("x", maxCaptchaToken+1)})
	if errCode(err) != risk.CodeCaptchaRequired || v.calls != 0 {
		t.Fatalf("oversized token: err=%v calls=%d", err, v.calls)
	}
}

func TestCheckCaptchaOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		answer risk.Answer
		err    error
		check  risk.CaptchaCheck
		hosts  []string
		want   string
		fail   bool
	}{
		{name: "pass", answer: risk.Answer{Success: true}, want: risk.CaptchaPassed},
		{name: "rejected", answer: risk.Answer{Success: false, Codes: []string{"invalid-input-response"}}, fail: true},
		{name: "timeout fails open", err: errx.External("timeout"), want: risk.CaptchaUnavailable},
		{name: "other error fails open", err: errors.New("boom"), want: risk.CaptchaUnavailable},
		{name: "headless hostname mismatch", answer: risk.Answer{Success: true, Hostname: "evil.example"}, hosts: []string{"app.example.com"}, fail: true},
		{name: "headless hostname match", answer: risk.Answer{Success: true, Hostname: "app.example.com"}, hosts: []string{"app.example.com"}, want: risk.CaptchaPassed},
		{name: "headless issuer host also accepted", answer: risk.Answer{Success: true, Hostname: "auth.example.com"}, hosts: []string{"app.example.com"}, want: risk.CaptchaPassed},
		{name: "action mismatch", answer: risk.Answer{Success: true, Action: "signup"}, check: risk.CaptchaCheck{Action: risk.CaptchaLogin}, fail: true},
		{name: "action match", answer: risk.Answer{Success: true, Action: "login"}, check: risk.CaptchaCheck{Action: risk.CaptchaLogin}, want: risk.CaptchaPassed},
		{name: "no action reported", answer: risk.Answer{Success: true}, check: risk.CaptchaCheck{Action: risk.CaptchaLogin}, want: risk.CaptchaPassed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := configuredCaptcha()
			repo.cfg.Hostnames = c.hosts
			v := &fakeSiteverify{answer: c.answer, err: c.err}
			s := newCaptchaService(t, repo, v, captchaFlags{config.FeatureCaptcha: true})
			check := c.check
			check.Environment, check.Surface, check.Token = captchaEnv, risk.SurfaceHeadless, "tok"
			out, err := s.CheckCaptcha(context.Background(), check)
			if c.fail {
				if errCode(err) != risk.CodeCaptchaRequired {
					t.Fatalf("err = %v, want CAPTCHA_REQUIRED", err)
				}
				return
			}
			if err != nil || out != c.want {
				t.Fatalf("out=%q err=%v, want %q", out, err, c.want)
			}
			if v.secret != "secret" {
				t.Fatalf("the provider got secret %q", v.secret)
			}
		})
	}
}

func TestCheckCaptchaHostedHostname(t *testing.T) {
	v := &fakeSiteverify{answer: risk.Answer{Success: true, Hostname: "other.example"}}
	s := newCaptchaService(t, configuredCaptcha(), v, captchaFlags{config.FeatureCaptcha: true})
	_, err := s.CheckCaptcha(context.Background(), risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHosted, Token: "t"})
	if errCode(err) != risk.CodeCaptchaRequired {
		t.Fatalf("hosted token solved elsewhere: %v", err)
	}
	if v.check.Hostname != "auth.example.com" {
		t.Fatalf("hostname checked = %q", v.check.Hostname)
	}
	v.answer.Hostname = "AUTH.example.com"
	if out, err := s.CheckCaptcha(context.Background(), risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHosted, Token: "t"}); err != nil || out != risk.CaptchaPassed {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestSaveCaptchaSealsAndKeepsSecret(t *testing.T) {
	repo := &fakeCaptchaRepo{}
	s := newCaptchaService(t, repo, &fakeSiteverify{}, nil)
	secret := "hunter-two"
	m := risk.Mutation{Environment: captchaEnv}
	out, err := s.SaveCaptcha(context.Background(), m, risk.CaptchaInput{Provider: risk.ProviderTurnstile, SiteKey: "k", Secret: &secret})
	if err != nil {
		t.Fatal(err)
	}
	if repo.sealed != "sealed:hunter-two" || !out.Hosted || !out.Headless {
		t.Fatalf("sealed=%q out=%+v", repo.sealed, out)
	}
	// No secret keeps the stored one for the same provider.
	if _, err := s.SaveCaptcha(context.Background(), m, risk.CaptchaInput{Provider: risk.ProviderTurnstile, SiteKey: "k2"}); err != nil || repo.sealed != "sealed:hunter-two" {
		t.Fatalf("err=%v sealed=%q", err, repo.sealed)
	}
	// Switching provider needs a new secret.
	if _, err := s.SaveCaptcha(context.Background(), m, risk.CaptchaInput{Provider: risk.ProviderHCaptcha, SiteKey: "k"}); err == nil {
		t.Fatal("switching provider without a secret was accepted")
	}
	if got := strings.Join(repo.audits, ","); got != risk.ActionCaptchaUpdate+","+risk.ActionCaptchaUpdate {
		t.Fatalf("audits = %s", got)
	}
}

func TestSaveCaptchaNeedsCipherAndSecret(t *testing.T) {
	repo := &fakeCaptchaRepo{}
	s := New(Deps{Captchas: repo, Verifier: &fakeSiteverify{}})
	secret := "x"
	_, err := s.SaveCaptcha(context.Background(), risk.Mutation{Environment: captchaEnv}, risk.CaptchaInput{Provider: risk.ProviderTurnstile, SiteKey: "k", Secret: &secret})
	if errCode(err) != "ENCRYPTION_KEY_REQUIRED" {
		t.Fatalf("err = %v", err)
	}
	s = newCaptchaService(t, repo, &fakeSiteverify{}, nil)
	if _, err := s.SaveCaptcha(context.Background(), risk.Mutation{Environment: captchaEnv}, risk.CaptchaInput{Provider: risk.ProviderTurnstile, SiteKey: "k"}); err == nil {
		t.Fatal("first save without a secret was accepted")
	}
}

func TestTestCaptcha(t *testing.T) {
	cases := []struct {
		name   string
		answer risk.Answer
		err    error
		want   string
	}{
		{name: "invalid response proves the secret", answer: risk.Answer{Codes: []string{"invalid-input-response"}}},
		{name: "invalid secret", answer: risk.Answer{Codes: []string{"invalid-input-secret"}}, want: risk.CodeCaptchaSecretInvalid},
		{name: "provider down", err: errx.External("down"), want: "EXTERNAL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newCaptchaService(t, configuredCaptcha(), &fakeSiteverify{answer: c.answer, err: c.err}, nil)
			err := s.TestCaptcha(context.Background(), captchaEnv)
			var e *errx.Error
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("err = %v", err)
			case c.want == risk.CodeCaptchaSecretInvalid && errCode(err) != c.want:
				t.Fatalf("err = %v", err)
			case c.want == "EXTERNAL" && (!errx.As(err, &e) || e.Type != errx.TypeExternal):
				t.Fatalf("err = %v", err)
			}
		})
	}
	if err := newCaptchaService(t, &fakeCaptchaRepo{}, &fakeSiteverify{}, nil).TestCaptcha(context.Background(), captchaEnv); err == nil {
		t.Fatal("testing without a configuration succeeded")
	}
}

func TestPasses(t *testing.T) {
	repo := &fakeCaptchaRepo{}
	s := newCaptchaService(t, repo, &fakeSiteverify{}, nil)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	ctx := context.Background()
	if ok, _ := s.Passed(ctx, captchaEnv, []byte("t")); ok {
		t.Fatal("pass before it was granted")
	}
	if err := s.GrantPass(ctx, captchaEnv, []byte("t")); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Passed(ctx, captchaEnv, []byte("t")); !ok {
		t.Fatal("granted pass not found")
	}
	if ok, _ := s.Passed(ctx, captchaEnv, []byte("other")); ok {
		t.Fatal("pass of another ticket")
	}
	for i := 0; i < config.CaptchaPassUses; i++ {
		if ok, err := s.UsePass(ctx, captchaEnv, []byte("t")); err != nil || !ok {
			t.Fatalf("use %d refused: %v", i+1, err)
		}
	}
	if ok, _ := s.UsePass(ctx, captchaEnv, []byte("t")); ok {
		t.Fatal("pass covered more posts than config.CaptchaPassUses")
	}
	if ok, _ := s.Passed(ctx, captchaEnv, []byte("t")); ok {
		t.Fatal("spent pass still reported")
	}
	if err := s.GrantPass(ctx, captchaEnv, []byte("t")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(config.CaptchaPassTTL + time.Second)
	if ok, _ := s.Passed(ctx, captchaEnv, []byte("t")); ok {
		t.Fatal("pass outlived its TTL")
	}
}

// A configuration that cannot be read never turns the CAPTCHA off.
func TestCaptchaLookupFailureFailsClosed(t *testing.T) {
	repo := &fakeCaptchaRepo{err: errx.Internal("database down")}
	s := newCaptchaService(t, repo, &fakeSiteverify{}, nil)
	ctx := context.Background()
	if _, err := s.CheckCaptcha(ctx, risk.CaptchaCheck{Environment: captchaEnv, Surface: risk.SurfaceHeadless}); err == nil {
		t.Fatal("check passed while the configuration could not be read")
	}
	if _, err := s.PublicCaptcha(ctx, captchaEnv, risk.SurfaceHosted); err == nil {
		t.Fatal("public CAPTCHA reported none while the configuration could not be read")
	}
}
