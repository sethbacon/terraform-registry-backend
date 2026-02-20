package jobs

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NewTagVerifier — interval defaulting
// ---------------------------------------------------------------------------

func TestNewTagVerifier_ZeroInterval_Defaults24h(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 0)
	if tv == nil {
		t.Fatal("NewTagVerifier returned nil")
	}
	if tv.interval != 24*time.Hour {
		t.Errorf("interval = %v, want 24h", tv.interval)
	}
}

func TestNewTagVerifier_NegativeInterval_Defaults24h(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, -5)
	if tv.interval != 24*time.Hour {
		t.Errorf("interval = %v, want 24h", tv.interval)
	}
}

func TestNewTagVerifier_CustomInterval(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 48)
	if tv.interval != 48*time.Hour {
		t.Errorf("interval = %v, want 48h", tv.interval)
	}
}

func TestNewTagVerifier_OneHour(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 1)
	if tv.interval != time.Hour {
		t.Errorf("interval = %v, want 1h", tv.interval)
	}
}

// ---------------------------------------------------------------------------
// NewTagVerifier — struct fields
// ---------------------------------------------------------------------------

func TestNewTagVerifier_StopChanInitialised(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 1)
	if tv.stopChan == nil {
		t.Error("stopChan should not be nil")
	}
}

func TestNewTagVerifier_StoresNilRepos(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 6)
	if tv.scmRepo != nil {
		t.Error("expected nil scmRepo")
	}
	if tv.moduleRepo != nil {
		t.Error("expected nil moduleRepo")
	}
	if tv.tokenCipher != nil {
		t.Error("expected nil tokenCipher")
	}
}

// ---------------------------------------------------------------------------
// Stop — should not panic
// ---------------------------------------------------------------------------

func TestTagVerifier_Stop_DoesNotPanic(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 1)
	// Stop closes the channel; calling it once must not panic
	tv.Stop()
}

// ---------------------------------------------------------------------------
// Start — using context cancellation to terminate quickly
// ---------------------------------------------------------------------------

func TestTagVerifier_Start_CancelContext(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		tv.Start(ctx)
		close(done)
	}()

	// Cancel immediately after a short delay
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Start returned after context cancellation
	case <-time.After(3 * time.Second):
		t.Error("Start did not return after context cancellation")
	}
}

func TestTagVerifier_Start_StopChannel(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 1)

	ctx := context.Background()
	done := make(chan struct{})

	go func() {
		tv.Start(ctx)
		close(done)
	}()

	// Stop via Stop() method
	time.Sleep(10 * time.Millisecond)
	tv.Stop()

	select {
	case <-done:
		// Start returned after Stop
	case <-time.After(3 * time.Second):
		t.Error("Start did not return after Stop()")
	}
}

// ---------------------------------------------------------------------------
// runVerification — direct call (no-op implementation, just logs)
// ---------------------------------------------------------------------------

func TestTagVerifier_RunVerification(t *testing.T) {
	tv := NewTagVerifier(nil, nil, nil, 24)
	// Should not panic or error
	tv.runVerification(context.Background())
}
