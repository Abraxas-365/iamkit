package user

import (
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
)

func TestPhoneVerificationSend(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	code := func(err error) string {
		var e *errx.Error
		if errx.As(err, &e) && e != nil {
			return e.Code
		}
		return ""
	}
	p, err := PhoneVerification{}.Send("+15551234567", []byte("h"), now)
	if err != nil || p.Phone != "+15551234567" || p.CodesSent != 1 || !p.Expires.Equal(now.Add(config.FactorCodeTTL)) || !p.Pending(now) {
		t.Fatalf("first send = %+v %v", p, err)
	}
	if _, err = p.Send("+15551234567", []byte("h"), now.Add(time.Second)); code(err) != "CODE_COOLDOWN" {
		t.Fatalf("cooldown = %v", err)
	}
	// Switching numbers keeps the hourly count.
	at := now
	for i := 1; i < config.FactorCodesPerHour; i++ {
		at = at.Add(config.FactorCodeCooldown)
		if p, err = p.Send("+1555000000"+string(rune('0'+i%10)), []byte("h"), at); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if _, err = p.Send("+15559999999", []byte("h"), at.Add(config.FactorCodeCooldown)); code(err) != "CODE_LIMIT" {
		t.Fatalf("hourly cap = %v", err)
	}
	if p, err = p.Send("+15559999999", []byte("h"), now.Add(time.Hour)); err != nil || p.CodesSent != 1 {
		t.Fatalf("new window = %+v %v", p, err)
	}
	if p.Pending(now.Add(time.Hour + config.FactorCodeTTL)) {
		t.Fatal("expired code pending")
	}
}

func TestMaskPhone(t *testing.T) {
	if got := MaskPhone("+15557654321"); got != "+1••••••••21" {
		t.Fatalf("mask = %q", got)
	}
}

func TestFreshAuth(t *testing.T) {
	now := time.Now()
	if FreshAuth(now.Unix(), now) != nil {
		t.Fatal("fresh refused")
	}
	if FreshAuth(0, now) == nil || FreshAuth(now.Add(-config.MFAFreshAuth-time.Minute).Unix(), now) == nil {
		t.Fatal("stale accepted")
	}
}
