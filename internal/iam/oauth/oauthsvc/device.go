package oauthsvc

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
)

var _ oauth.Devices = (*Service)(nil)

// AuthorizeDevice starts a device authorization (RFC 8628 §3.1) for a
// client allowed the device grant.
func (s *Service) AuthorizeDevice(ctx context.Context, client *oauth.Client, scope string) (oauth.DeviceAuthorization, error) {
	if !client.Allows(oauth.GrantDeviceCode) || !client.HostedLogin {
		return oauth.DeviceAuthorization{}, oauth.DeviceError("unauthorized_client")
	}
	scope = strings.Join(strings.Fields(scope), " ")
	if scope == "" {
		scope = "openid"
	}
	if err := oauth.ValidateDeviceScope(scope); err != nil {
		return oauth.DeviceAuthorization{}, oauth.DeviceError("invalid_scope")
	}
	device, deviceHash, err := s.secrets.Generate("ik_device_")
	if err != nil {
		return oauth.DeviceAuthorization{}, err
	}
	// A user code collision (unique hash) is retried with a new code.
	for range 3 {
		code, err := userCode()
		if err != nil {
			return oauth.DeviceAuthorization{}, err
		}
		err = s.repository.CreateDevice(ctx, client, deviceHash, s.secrets.Hash(code), scope, oauth.DeviceInterval, oauth.DeviceCodeTTL)
		var e *errx.Error
		if errx.As(err, &e) && e.Type == errx.TypeConflict {
			continue
		}
		if err != nil {
			return oauth.DeviceAuthorization{}, err
		}
		return oauth.DeviceAuthorization{DeviceCode: device, UserCode: oauth.FormatUserCode(code), ExpiresIn: int(oauth.DeviceCodeTTL / time.Second), Interval: int(oauth.DeviceInterval / time.Second)}, nil
	}
	return oauth.DeviceAuthorization{}, errx.Internal("could not allocate a user code")
}

// userCode draws UserCodeLength characters of UserCodeAlphabet.
func userCode() (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(oauth.UserCodeAlphabet)))
	for range oauth.UserCodeLength {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", errx.Wrap(err, "user code generation failed", errx.TypeInternal)
		}
		b.WriteByte(oauth.UserCodeAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// RedeemDevice answers one token request of the device grant: pending,
// slow down, expired, denied, or the approved session (once). The session
// must still be live and grant access to the client's resource.
func (s *Service) RedeemDevice(ctx context.Context, client *oauth.Client, deviceCode string) (oauth.DeviceGrant, error) {
	if !client.Allows(oauth.GrantDeviceCode) {
		return oauth.DeviceGrant{}, oauth.DeviceError("unauthorized_client")
	}
	if !strings.HasPrefix(deviceCode, "ik_device_") {
		return oauth.DeviceGrant{}, oauth.DeviceError(oauth.DeviceInvalidGrant)
	}
	device, err := s.repository.PollDevice(ctx, client, s.secrets.Hash(deviceCode), func(d oauth.Device) (oauth.Device, error) {
		return d.Poll(time.Now())
	})
	if err != nil {
		return oauth.DeviceGrant{}, err
	}
	info, err := s.repository.SessionInfo(ctx, device.Session)
	if err != nil {
		return oauth.DeviceGrant{}, err
	}
	access, err := s.Access(ctx, client, device.User, device.Session, device.Organization)
	if err != nil {
		return oauth.DeviceGrant{}, oauth.DeviceError(oauth.DeviceInvalidGrant)
	}
	login := oauth.Login{User: device.User, Organization: device.Organization, Session: device.Session, Permissions: access.Permissions}
	return oauth.DeviceGrant{Login: login, Scopes: strings.Fields(device.Scope), Session: info, Requested: device.Created}, nil
}

// pendingDevice is the pending device a typed user code names.
func (s *Service) pendingDevice(ctx context.Context, userCode string) (oauth.Device, []byte, error) {
	code := oauth.NormalizeUserCode(userCode)
	if code == "" {
		return oauth.Device{}, nil, errx.NotFound("device code not found")
	}
	hash := s.secrets.Hash(code)
	device, err := s.repository.PendingDevice(ctx, hash)
	return device, hash, err
}

func (s *Service) DeviceRequest(ctx context.Context, userCode string) (oauth.DeviceRequest, error) {
	device, _, err := s.pendingDevice(ctx, userCode)
	if err != nil {
		return oauth.DeviceRequest{}, err
	}
	return oauth.DeviceRequest{Client: device.Client, Environment: device.Environment, Application: device.ApplicationName, Scopes: strings.Fields(device.Scope)}, nil
}

func (s *Service) StartDevice(ctx context.Context, userCode string) (string, string, error) {
	device, _, err := s.pendingDevice(ctx, userCode)
	if err != nil {
		return "", "", err
	}
	client, err := s.Client(ctx, device.Client)
	if err != nil {
		return "", "", err
	}
	if !client.HostedLogin || !client.Allows(oauth.GrantDeviceCode) {
		return "", "", errx.Forbidden("client does not use the device grant")
	}
	ticket, hash, err := s.secrets.Generate("ik_authorize_")
	if err != nil {
		return "", "", err
	}
	binding, bindingHash, err := s.secrets.Generate("ik_browser_")
	if err != nil {
		return "", "", err
	}
	return ticket, binding, s.repository.SaveDeviceTicket(ctx, hash, bindingHash, client, device.Hash)
}

func (s *Service) DenyDevice(ctx context.Context, userCode string) error {
	code := oauth.NormalizeUserCode(userCode)
	if code == "" {
		return errx.NotFound("device code not found")
	}
	return s.repository.DenyDevice(ctx, s.secrets.Hash(code))
}
