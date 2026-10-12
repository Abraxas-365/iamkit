package samlsvc

import (
	"context"
	"log/slog"
	"sync"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// logout holds single logout's collaborators.
type logout struct {
	repository samlidp.LogoutRepository
	protocol   samlidp.LogoutProtocol
	sender     samlidp.LogoutSender
}

// SetLogout turns on single logout: sessions are linked to the
// applications that received assertions for them, inbound LogoutRequests
// are served and back-channel notifications are sent.
func (s *Service) SetLogout(repository samlidp.LogoutRepository, protocol samlidp.LogoutProtocol, sender samlidp.LogoutSender) {
	s.logout = &logout{repository: repository, protocol: protocol, sender: sender}
}

// refusedLogout is the one answer for every request that cannot be
// trusted (unknown issuer, single logout off, bad signature): it tells a
// caller nothing about which applications exist.
func refusedLogout() error {
	return errx.Unauthorized("the LogoutRequest is refused")
}

func (s *Service) Logout(ctx context.Context, environment identity.EnvironmentID, m samlidp.LogoutMessage) (samlidp.LogoutAnswer, error) {
	if s.logout == nil {
		return samlidp.LogoutAnswer{}, errx.NotFound("not found")
	}
	if err := m.Validate(); err != nil {
		return samlidp.LogoutAnswer{}, err
	}
	if err := s.environment(ctx, environment); err != nil {
		return samlidp.LogoutAnswer{}, err
	}
	request, err := s.logout.protocol.DecodeLogout(m)
	if err != nil {
		return samlidp.LogoutAnswer{}, err
	}
	sp, err := s.repository.FindEntity(ctx, environment, request.Issuer)
	if err != nil || !sp.SingleLogout() || sp.SLOURL == "" {
		return samlidp.LogoutAnswer{}, refusedLogout()
	}
	if err := s.logout.protocol.VerifyLogout(m, sp); err != nil {
		return samlidp.LogoutAnswer{}, refusedLogout()
	}
	idp, err := s.protocol.IdentityProvider(ctx, environment)
	if err != nil {
		return samlidp.LogoutAnswer{}, err
	}
	if err := request.Check(idp.SLOURL, s.now()); err != nil {
		return samlidp.LogoutAnswer{}, err
	}
	// A request without SessionIndex would name every session of the
	// principal at the application; IAMKit ends only sessions an assertion
	// named, so it matches nothing.
	status := samlidp.StatusRequester
	for _, index := range request.SessionIndexes {
		session, err := identity.ParseSessionID(index)
		if err != nil {
			continue
		}
		m := samlidp.Mutation{Environment: environment, Action: samlidp.ActionLogout, Target: sp.ID.String()}
		ended, err := s.logout.repository.EndSession(ctx, m, sp.ID, session, request.NameID)
		if err != nil {
			return samlidp.LogoutAnswer{}, err
		}
		if ended {
			status = samlidp.StatusSuccess
		}
	}
	return s.logout.protocol.LogoutResponse(ctx, environment, sp, request, status)
}

func (s *Service) DispatchLogouts(ctx context.Context) (bool, error) {
	if s.logout == nil {
		return false, nil
	}
	due, err := s.logout.repository.ClaimLogouts(ctx, samlidp.LogoutBatch)
	if err != nil {
		return false, err
	}
	var wg sync.WaitGroup
	for _, n := range due {
		wg.Add(1)
		go func(n samlidp.LogoutNotification) {
			defer wg.Done()
			s.deliver(ctx, n)
		}(n)
	}
	wg.Wait()
	return len(due) == samlidp.LogoutBatch, nil
}

func (s *Service) send(ctx context.Context, n samlidp.LogoutNotification) error {
	if n.ServiceProvider.SLOSOAPURL == "" {
		return errx.Business("the application no longer has a back-channel logout URL")
	}
	envelope, err := s.logout.protocol.BackchannelLogout(ctx, n)
	if err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(ctx, samlidp.LogoutTimeout)
	defer cancel()
	return s.logout.sender.Send(sendCtx, n.ServiceProvider.SLOSOAPURL, envelope)
}

func (s *Service) deliver(ctx context.Context, n samlidp.LogoutNotification) {
	repository := s.logout.repository
	err := s.send(ctx, n)
	if err == nil {
		if err = repository.LogoutDelivered(ctx, n.ID); err != nil {
			slog.Error("record SAML logout delivery", "notification", n.ID, "error", err)
		}
		return
	}
	if ctx.Err() != nil {
		// Shutting down: the lease expires and another round retries.
		return
	}
	problem := err.Error()
	if n.Attempts < samlidp.LogoutMaxAttempts && n.ServiceProvider.SLOSOAPURL != "" {
		slog.Warn("SAML logout failed, will retry", "service_provider", n.ServiceProvider.ID, "attempt", n.Attempts, "error", problem)
		err = repository.LogoutRetry(ctx, n.ID, s.now().Add(samlidp.LogoutRetryAfter(n.Attempts)), problem)
	} else {
		slog.Warn("SAML logout given up", "service_provider", n.ServiceProvider.ID, "attempts", n.Attempts, "error", problem)
		err = repository.LogoutFailed(ctx, n, problem)
	}
	if err != nil {
		slog.Error("record SAML logout failure", "notification", n.ID, "error", err)
	}
}

func (s *Service) PruneLogouts(ctx context.Context) error {
	if s.logout == nil {
		return nil
	}
	return s.logout.repository.PruneLogouts(ctx, s.now().Add(-samlidp.LogoutRetention))
}
