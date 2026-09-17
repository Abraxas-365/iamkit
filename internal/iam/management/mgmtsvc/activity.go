package mgmtsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/google/uuid"
)

type Activity struct{ repository management.ActivityRepository }

func NewActivity(r management.ActivityRepository) *Activity { return &Activity{r} }
func (s *Activity) Sessions(ctx context.Context, environment string) ([]management.Session, error) {
	return s.repository.Sessions(ctx, environment)
}
func (s *Activity) Audit(ctx context.Context, environment string) ([]management.AuditEvent, error) {
	return s.repository.Audit(ctx, environment)
}

var _ management.ActivityCommands = (*Activity)(nil)
var _ management.ActivityQueries = (*Activity)(nil)

func (s *Activity) RevokeSession(ctx context.Context, environment, id, actor, action, target string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errx.NotFound("session not found")
	}
	return s.repository.RevokeSession(ctx, environment, id, actor, action, target)
}
