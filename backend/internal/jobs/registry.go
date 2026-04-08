package jobs

import (
	"context"
	"log/slog"
	"sync"
)

// Job is the interface all background jobs must implement.
type Job interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
}

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
		go func() {
			if err := j.Start(ctx); err != nil {
				slog.Error("job failed to start", "job", j.Name(), "error", err)
			}
		}()
	}
}

func (r *Registry) StopAll() {
	for _, j := range r.jobs {
		if err := j.Stop(); err != nil {
			slog.Error("job failed to stop cleanly", "job", j.Name(), "error", err)
		}
	}
}
