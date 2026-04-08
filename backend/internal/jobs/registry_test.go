package jobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fake Job implementation for testing
// ---------------------------------------------------------------------------

type fakeJob struct {
	name    string
	started bool
	stopped bool
	startErr error
	stopErr  error
}

func (f *fakeJob) Name() string { return f.name }
func (f *fakeJob) Start(_ context.Context) error {
	f.started = true
	return f.startErr
}
func (f *fakeJob) Stop() error {
	f.stopped = true
	return f.stopErr
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
	j := &fakeJob{name: "test-job"}
	r.Register(j)
	if len(r.jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(r.jobs))
	}
}

func TestRegistry_Register_Multiple(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeJob{name: "a"})
	r.Register(&fakeJob{name: "b"})
	if len(r.jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(r.jobs))
	}
}

// ---------------------------------------------------------------------------
// StartAll
// ---------------------------------------------------------------------------

func TestRegistry_StartAll(t *testing.T) {
	r := NewRegistry()
	j := &fakeJob{name: "job1"}
	r.Register(j)

	ctx := context.Background()
	r.StartAll(ctx)

	// Give goroutine time to start
	time.Sleep(10 * time.Millisecond)
	if !j.started {
		t.Error("expected job to be started")
	}
}

func TestRegistry_StartAll_JobError(t *testing.T) {
	r := NewRegistry()
	j := &fakeJob{name: "failing-job", startErr: errors.New("start failed")}
	r.Register(j)

	ctx := context.Background()
	r.StartAll(ctx) // should log error but not panic

	time.Sleep(10 * time.Millisecond)
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
	j := &fakeJob{name: "job1"}
	r.Register(j)
	r.StopAll()
	if !j.stopped {
		t.Error("expected job to be stopped")
	}
}

func TestRegistry_StopAll_JobError(t *testing.T) {
	r := NewRegistry()
	j := &fakeJob{name: "failing-stop", stopErr: errors.New("stop failed")}
	r.Register(j)
	r.StopAll() // should log error but not panic
}

func TestRegistry_StopAll_Empty(t *testing.T) {
	r := NewRegistry()
	r.StopAll() // no-op, should not panic
}
