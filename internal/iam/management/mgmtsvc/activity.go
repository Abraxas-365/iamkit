package mgmtsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Activity struct{ repository management.ActivityRepository }

func NewActivity(r management.ActivityRepository) *Activity { return &Activity{r} }
func (s *Activity) Sessions(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[management.Session], error) {
	return s.repository.Sessions(ctx, environment, page)
}
func (s *Activity) Audit(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[management.AuditEvent], error) {
	return s.repository.Audit(ctx, environment, page)
}

var _ management.ActivityCommands = (*Activity)(nil)
var _ management.ActivityQueries = (*Activity)(nil)

func (s *Activity) RevokeSession(ctx context.Context, environment identity.EnvironmentID, id identity.SessionID, actor, action, target string) error {
	if id.IsZero() {
		return errx.NotFound("session not found")
	}
	return s.repository.RevokeSession(ctx, environment, id, actor, action, target)
}
