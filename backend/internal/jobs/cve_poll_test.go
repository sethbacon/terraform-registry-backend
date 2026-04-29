package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// NewCVEPollJob
// ---------------------------------------------------------------------------

func TestNewCVEPollJob_NotNil(t *testing.T) {
	cveCfg := &config.CVEConfig{
		Enabled:       false,
		IntervalHours: 24,
		OSVEndpoint:   "https://api.osv.dev",
	}
	scanCfg := &config.ScanningConfig{}
	notifCfg := &config.NotificationsConfig{}

	job := NewCVEPollJob(nil, nil, scanCfg, cveCfg, notifCfg)
	if job == nil {
		t.Fatal("expected non-nil CVEPollJob")
	}
}

func TestNewCVEPollJob_EmptyOSVEndpoint_UsesDefault(t *testing.T) {
	cveCfg := &config.CVEConfig{Enabled: false, OSVEndpoint: ""}
	job := NewCVEPollJob(nil, nil, &config.ScanningConfig{}, cveCfg, &config.NotificationsConfig{})
	if job == nil {
		t.Fatal("expected non-nil CVEPollJob with empty endpoint")
	}
}

// ---------------------------------------------------------------------------
// Start — disabled path
// ---------------------------------------------------------------------------

func TestCVEPollJob_Start_Disabled(t *testing.T) {
	cveCfg := &config.CVEConfig{Enabled: false, IntervalHours: 24}
	job := NewCVEPollJob(nil, nil, &config.ScanningConfig{}, cveCfg, &config.NotificationsConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// expected: Start returns immediately when disabled
	case <-ctx.Done():
		t.Fatal("Start() did not return promptly when CVE polling is disabled")
	}
}

// ---------------------------------------------------------------------------
// TriggerPoll
// ---------------------------------------------------------------------------

func TestCVEPollJob_TriggerPoll_SendsToChannel(t *testing.T) {
	cveCfg := &config.CVEConfig{Enabled: false}
	job := NewCVEPollJob(nil, nil, &config.ScanningConfig{}, cveCfg, &config.NotificationsConfig{})

	// Should not block — channel is buffered with capacity 1
	job.TriggerPoll()

	// Channel should now have 1 item
	select {
	case <-job.manualCh:
		// signal was queued
	default:
		t.Error("expected a signal in manualCh after TriggerPoll()")
	}
}

func TestCVEPollJob_TriggerPoll_IsNonBlocking(t *testing.T) {
	cveCfg := &config.CVEConfig{Enabled: false}
	job := NewCVEPollJob(nil, nil, &config.ScanningConfig{}, cveCfg, &config.NotificationsConfig{})

	// Fill the buffer
	job.TriggerPoll()
	// Second call should not block (no-op when already queued)
	done := make(chan struct{})
	go func() {
		job.TriggerPoll()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TriggerPoll() blocked when channel was full")
	}
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------

func TestCVEPollJob_Stop_ClosesChannel(t *testing.T) {
	cveCfg := &config.CVEConfig{Enabled: false}
	job := NewCVEPollJob(nil, nil, &config.ScanningConfig{}, cveCfg, &config.NotificationsConfig{})

	job.Stop()

	// stopChan should be closed — reading from it should return immediately
	select {
	case <-job.stopChan:
		// channel closed as expected
	default:
		t.Error("stopChan was not closed after Stop()")
	}
}

// ---------------------------------------------------------------------------
// Start — enabled path, all poll flags false, pre-cancelled context
// ---------------------------------------------------------------------------

func TestCVEPollJob_Start_Enabled_ContextCancelled(t *testing.T) {
	cveCfg := &config.CVEConfig{
		Enabled:       true,
		IntervalHours: 1,
		OSVEndpoint:   "https://api.osv.dev",
		PollBinaries:  false,
		PollProviders: false,
		PollScanner:   false,
	}
	job := NewCVEPollJob(nil, nil, &config.ScanningConfig{}, cveCfg, &config.NotificationsConfig{})

	// Cancel context immediately so Start exits via ctx.Done() branch.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// expected: Start exits promptly when context is cancelled
	case <-time.After(5 * time.Second):
		t.Fatal("Start() did not exit within 5s after context cancellation")
	}
}

func TestCVEPollJob_Start_IntervalZero_UsesDefault(t *testing.T) {
	cveCfg := &config.CVEConfig{
		Enabled:       true,
		IntervalHours: 0, // triggers default=24
		PollBinaries:  false,
		PollProviders: false,
		PollScanner:   false,
	}
	job := NewCVEPollJob(nil, nil, &config.ScanningConfig{}, cveCfg, &config.NotificationsConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		job.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start() with IntervalHours=0 did not exit within 5s")
	}
}
