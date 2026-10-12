package orgadminsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// App audit logs and log streams. Everything is scoped to the principal's
// organization: the event filter's organization is forced and only the
// organization's own streams are reachable (an environment stream or
// another organization's is not found).

func (s *Service) AuditLogs(ctx context.Context, p orgadmin.Principal, filter auditlog.Filter, limit int) (auditlog.Page, error) {
	if err := p.Require(authorization.PermOrgAuditRead); err != nil {
		return auditlog.Page{}, err
	}
	filter.Organization = p.Organization
	if err := filter.Validate(); err != nil {
		return auditlog.Page{}, err
	}
	return s.d.AuditLogs.List(ctx, p.Environment, filter, limit)
}

func (s *Service) ExportAuditLogs(ctx context.Context, p orgadmin.Principal, filter auditlog.Filter, write func(auditlog.Event) error) error {
	if err := p.Require(authorization.PermOrgAuditRead); err != nil {
		return err
	}
	filter.Organization = p.Organization
	if err := filter.Validate(); err != nil {
		return err
	}
	return s.d.AuditLogs.Export(ctx, p.Environment, filter, write)
}

func streamScope(p orgadmin.Principal) logstream.Scope {
	return logstream.OrganizationScope(p.Environment, p.Organization)
}

func streamMutation(p orgadmin.Principal, action string) logstream.Mutation {
	return logstream.Mutation{Scope: streamScope(p), Actor: p.Actor(), Action: action}
}

// requireStreamRead admits holders of the read permission and of the write
// permission (a setup link for log streams could not otherwise see what it
// created).
func requireStreamRead(p orgadmin.Principal) error {
	if p.Has(authorization.PermOrgLogStreamsWrite) {
		return nil
	}
	return p.Require(authorization.PermOrgAuditRead)
}

func (s *Service) LogStreams(ctx context.Context, p orgadmin.Principal) ([]logstream.Stream, error) {
	if err := requireStreamRead(p); err != nil {
		return nil, err
	}
	return s.d.LogStreamViews.List(ctx, streamScope(p))
}

func (s *Service) LogStream(ctx context.Context, p orgadmin.Principal, stream identity.LogStreamID) (logstream.Stream, error) {
	if err := requireStreamRead(p); err != nil {
		return logstream.Stream{}, err
	}
	return s.d.LogStreamViews.Find(ctx, streamScope(p), stream)
}

func (s *Service) LogStreamDeliveries(ctx context.Context, p orgadmin.Principal, stream identity.LogStreamID, filter logstream.DeliveryFilter, page query.Pagination) (query.Paginated[logstream.Delivery], error) {
	if err := requireStreamRead(p); err != nil {
		return query.Paginated[logstream.Delivery]{}, err
	}
	if err := filter.Validate(); err != nil {
		return query.Paginated[logstream.Delivery]{}, err
	}
	return s.d.LogStreamViews.ListDeliveries(ctx, streamScope(p), stream, filter, page)
}

func (s *Service) CreateLogStream(ctx context.Context, p orgadmin.Principal, input logstream.Create) (logstream.Created, error) {
	if err := p.Require(authorization.PermOrgLogStreamsWrite); err != nil {
		return logstream.Created{}, err
	}
	// The scope names the organization; a body that names another one is
	// refused by the service.
	input.Name = strings.TrimSpace(input.Name)
	input.Config = input.Config.Normalize()
	if err := input.Validate(); err != nil {
		return logstream.Created{}, err
	}
	return s.d.LogStreams.Create(ctx, streamMutation(p, logstream.ActionCreate), input)
}

func (s *Service) UpdateLogStream(ctx context.Context, p orgadmin.Principal, stream identity.LogStreamID, input logstream.Update) (logstream.Stream, error) {
	if err := p.Require(authorization.PermOrgLogStreamsWrite); err != nil {
		return logstream.Stream{}, err
	}
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		input.Name = &name
	}
	if err := input.Validate(); err != nil {
		return logstream.Stream{}, err
	}
	if err := s.d.LogStreams.Update(ctx, streamMutation(p, logstream.ActionUpdate), stream, input); err != nil {
		return logstream.Stream{}, err
	}
	return s.d.LogStreamViews.Find(ctx, streamScope(p), stream)
}

func (s *Service) EnableLogStream(ctx context.Context, p orgadmin.Principal, stream identity.LogStreamID) (logstream.Stream, error) {
	active := true
	return s.UpdateLogStream(ctx, p, stream, logstream.Update{Active: &active})
}

func (s *Service) DeleteLogStream(ctx context.Context, p orgadmin.Principal, stream identity.LogStreamID) error {
	if err := p.Require(authorization.PermOrgLogStreamsWrite); err != nil {
		return err
	}
	return s.d.LogStreams.Delete(ctx, streamMutation(p, logstream.ActionDelete), stream)
}

func (s *Service) RotateLogStreamSecret(ctx context.Context, p orgadmin.Principal, stream identity.LogStreamID) (logstream.Created, error) {
	if err := p.Require(authorization.PermOrgLogStreamsWrite); err != nil {
		return logstream.Created{}, err
	}
	return s.d.LogStreams.RotateSecret(ctx, streamMutation(p, logstream.ActionRotateSecret), stream)
}

func (s *Service) TestLogStream(ctx context.Context, p orgadmin.Principal, stream identity.LogStreamID) (logstream.TestResult, error) {
	if err := p.Require(authorization.PermOrgLogStreamsWrite); err != nil {
		return logstream.TestResult{}, err
	}
	return s.d.LogStreams.Test(ctx, streamScope(p), stream)
}

func (s *Service) RetryLogStreamDelivery(ctx context.Context, p orgadmin.Principal, stream identity.LogStreamID, delivery int64) error {
	if err := p.Require(authorization.PermOrgLogStreamsWrite); err != nil {
		return err
	}
	return s.d.LogStreams.RetryDelivery(ctx, streamMutation(p, logstream.ActionRetryDelivery), stream, delivery)
}
