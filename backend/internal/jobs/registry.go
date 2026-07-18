package jobs

import (
	"context"
	"log/slog"
	"sync"

	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"

	"github.com/terraform-registry/terraform-registry/internal/safego"
)

// Job is the interface all background jobs must implement.
type Job interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
}

// Compile-time assertions that every background job satisfies Job, so the
// Registry can start/stop them uniformly (issue #565 finding [40]).
var (
	_ Job = (*MirrorSyncJob)(nil)
	_ Job = (*TerraformMirrorSyncJob)(nil)
	_ Job = (*ReleasesKeyRefreshJob)(nil)
	_ Job = (*identitynotify.APIKeyExpiryNotifier)(nil)
	_ Job = (*ModuleScannerJob)(nil)
	_ Job = (*ScannerUpdateJob)(nil)
	_ Job = (*AuditCleanupJob)(nil)
	_ Job = (*WebhookRetryJob)(nil)
	_ Job = (*CVEPollJob)(nil)
)

// Registry manages the lifecycle of background jobs.
type Registry struct {
	jobs []Job
	mu   sync.Mutex
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(j Job) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs = append(r.jobs, j)
}

func (r *Registry) StartAll(ctx context.Context) {
	for _, j := range r.jobs {
		j := j
		safego.Go(func() {
			if err := j.Start(ctx); err != nil {
				slog.Error("job failed to start", "job", j.Name(), "error", err)
			}
		})
	}
}

func (r *Registry) StopAll() {
	for _, j := range r.jobs {
		if err := j.Stop(); err != nil {
			slog.Error("job failed to stop cleanly", "job", j.Name(), "error", err)
		}
	}
}
