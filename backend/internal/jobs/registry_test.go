package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Fake Job implementation for testing
// ---------------------------------------------------------------------------

type fakeJob struct {
	name     string
	startErr error
	stopErr  error

	mu      sync.Mutex
	started bool
	stopped bool
	startCh chan struct{} // closed when Start is called
}

func newFakeJob(name string) *fakeJob {
	return &fakeJob{name: name, startCh: make(chan struct{})}
}

func (f *fakeJob) Name() string { return f.name }
func (f *fakeJob) Start(_ context.Context) error {
	f.mu.Lock()
	f.started = true
	f.mu.Unlock()
	close(f.startCh)
	return f.startErr
}
func (f *fakeJob) Stop() error {
	f.mu.Lock()
	f.stopped = true
	f.mu.Unlock()
	return f.stopErr
}
func (f *fakeJob) wasStarted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
}
func (f *fakeJob) wasStopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped
}

// ---------------------------------------------------------------------------
// NewRegistry
// ---------------------------------------------------------------------------

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()
	j := newFakeJob("test-job")
	r.Register(j)
	if len(r.jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(r.jobs))
	}
}

func TestRegistry_Register_Multiple(t *testing.T) {
	r := NewRegistry()
	r.Register(newFakeJob("a"))
	r.Register(newFakeJob("b"))
	if len(r.jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(r.jobs))
	}
}

// ---------------------------------------------------------------------------
// StartAll
// ---------------------------------------------------------------------------

func TestRegistry_StartAll(t *testing.T) {
	r := NewRegistry()
	j := newFakeJob("job1")
	r.Register(j)

	ctx := context.Background()
	r.StartAll(ctx)

	// Wait for Start to be called (avoids the data race from time.Sleep).
	<-j.startCh
	if !j.wasStarted() {
		t.Error("expected job to be started")
	}
}

func TestRegistry_StartAll_JobError(t *testing.T) {
	r := NewRegistry()
	j := &fakeJob{name: "failing-job", startErr: errors.New("start failed"), startCh: make(chan struct{})}
	r.Register(j)

	ctx := context.Background()
	r.StartAll(ctx) // should log error but not panic

	<-j.startCh // wait for the goroutine to finish
}

func TestRegistry_StartAll_Empty(t *testing.T) {
	r := NewRegistry()
	r.StartAll(context.Background()) // no-op, should not panic
}

// ---------------------------------------------------------------------------
// StopAll
// ---------------------------------------------------------------------------

func TestRegistry_StopAll(t *testing.T) {
	r := NewRegistry()
	j := newFakeJob("job1")
	r.Register(j)
	r.StopAll()
	if !j.wasStopped() {
		t.Error("expected job to be stopped")
	}
}

func TestRegistry_StopAll_JobError(t *testing.T) {
	r := NewRegistry()
	j := &fakeJob{name: "failing-stop", stopErr: errors.New("stop failed"), startCh: make(chan struct{})}
	r.Register(j)
	r.StopAll() // should log error but not panic
}

func TestRegistry_StopAll_Empty(t *testing.T) {
	r := NewRegistry()
	r.StopAll() // no-op, should not panic
}
