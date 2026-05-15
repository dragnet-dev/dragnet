package sources

import (
	"context"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// Source is the common interface for all intelligence sources.
type Source interface {
	Name() string
	Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error)
}
