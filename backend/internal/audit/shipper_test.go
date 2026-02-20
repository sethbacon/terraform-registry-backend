package audit_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/audit"
)

// ---------------------------------------------------------------------------
// MultiShipper — via NewMultiShipper factory
// ---------------------------------------------------------------------------

func TestNewMultiShipper_Empty(t *testing.T) {
	ms, err := audit.NewMultiShipper(nil)
	if err != nil {
		t.Fatalf("NewMultiShipper(nil) error: %v", err)
	}
	if ms == nil {
		t.Fatal("NewMultiShipper returned nil")
	}
}

func TestMultiShipper_ShipEmpty(t *testing.T) {
	ms, _ := audit.NewMultiShipper(nil)
	if err := ms.Ship(context.Background(), &audit.LogEntry{Action: "test"}); err != nil {
		t.Errorf("Ship() on empty multi-shipper = %v, want nil", err)
	}
}

func TestMultiShipper_CloseEmpty(t *testing.T) {
	ms, _ := audit.NewMultiShipper(nil)
	if err := ms.Close(); err != nil {
		t.Errorf("Close() on empty multi-shipper = %v, want nil", err)
	}
}

func TestNewMultiShipper_DisabledConfigSkipped(t *testing.T) {
	cfgs := []audit.ShipperConfig{
		{Enabled: false, Type: "webhook", Webhook: &audit.WebhookConfig{URL: "http://example.com"}},
	}
	ms, err := audit.NewMultiShipper(cfgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Disabled config → acts as empty multi-shipper
	if err := ms.Ship(context.Background(), &audit.LogEntry{Action: "test"}); err != nil {
		t.Errorf("Ship() = %v, want nil", err)
	}
}

func TestNewMultiShipper_UnknownType(t *testing.T) {
	cfgs := []audit.ShipperConfig{{Enabled: true, Type: "foobar"}}
	if _, err := audit.NewMultiShipper(cfgs); err == nil {
		t.Error("expected error for unknown shipper type, got nil")
	}
}

func TestNewMultiShipper_WebhookNilConfig(t *testing.T) {
	cfgs := []audit.ShipperConfig{{Enabled: true, Type: "webhook", Webhook: nil}}
	if _, err := audit.NewMultiShipper(cfgs); err == nil {
		t.Error("expected error for webhook with nil config, got nil")
	}
}

func TestNewMultiShipper_FileNilConfig(t *testing.T) {
	cfgs := []audit.ShipperConfig{{Enabled: true, Type: "file", File: nil}}
	if _, err := audit.NewMultiShipper(cfgs); err == nil {
		t.Error("expected error for file with nil config, got nil")
	}
}

func TestMultiShipper_ContinuesAfterShipperError(t *testing.T) {
	// First server: returns 500 (causes WebhookShipper to return an error)
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv1.Close()

	// Second server: records successful delivery
	var srv2Count int
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		srv2Count++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	cfgs := []audit.ShipperConfig{
		{Enabled: true, Type: "webhook", Webhook: &audit.WebhookConfig{URL: srv1.URL, Timeout: time.Second}},
		{Enabled: true, Type: "webhook", Webhook: &audit.WebhookConfig{URL: srv2.URL, Timeout: time.Second}},
	}
	ms, err := audit.NewMultiShipper(cfgs)
	if err != nil {
		t.Fatalf("NewMultiShipper error: %v", err)
	}
	defer ms.Close()

	shipErr := ms.Ship(context.Background(), &audit.LogEntry{Action: "test"})
	if shipErr == nil {
		t.Error("Ship() = nil, want error from first shipper")
	}
	if srv2Count != 1 {
		t.Errorf("second shipper received %d calls, want 1", srv2Count)
	}
}

// ---------------------------------------------------------------------------
// WebhookShipper
// ---------------------------------------------------------------------------

func TestWebhookShipper_ShipEntry(t *testing.T) {
	var received bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		received.ReadFrom(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws, err := audit.NewWebhookShipper(&audit.WebhookConfig{
		URL:     srv.URL,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewWebhookShipper error: %v", err)
	}
	defer ws.Close()

	entry := &audit.LogEntry{Action: "webhook.test", UserID: "u1", StatusCode: 200}
	if err := ws.Ship(context.Background(), entry); err != nil {
		t.Fatalf("Ship() error: %v", err)
	}

	var decoded audit.LogEntry
	if err := json.Unmarshal(received.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if decoded.Action != entry.Action {
		t.Errorf("Action = %q, want %q", decoded.Action, entry.Action)
	}
	if decoded.UserID != entry.UserID {
		t.Errorf("UserID = %q, want %q", decoded.UserID, entry.UserID)
	}
}

func TestWebhookShipper_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ws, _ := audit.NewWebhookShipper(&audit.WebhookConfig{URL: srv.URL, Timeout: 5 * time.Second})
	defer ws.Close()

	if err := ws.Ship(context.Background(), &audit.LogEntry{Action: "err"}); err == nil {
		t.Error("Ship() = nil, want error for 500 response")
	}
}

func TestWebhookShipper_CustomHeader(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Auth-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws, _ := audit.NewWebhookShipper(&audit.WebhookConfig{
		URL:     srv.URL,
		Timeout: 5 * time.Second,
		Headers: map[string]string{"X-Auth-Token": "secret"},
	})
	defer ws.Close()

	ws.Ship(context.Background(), &audit.LogEntry{Action: "header.test"})
	if gotToken != "secret" {
		t.Errorf("X-Auth-Token = %q, want secret", gotToken)
	}
}

func TestWebhookShipper_Close(t *testing.T) {
	ws, err := audit.NewWebhookShipper(&audit.WebhookConfig{
		URL:     "http://localhost:0",
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewWebhookShipper: %v", err)
	}
	// Close should not panic
	if err := ws.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	// Second close should also not panic (closeOnce)
	ws.Close()
}

// ---------------------------------------------------------------------------
// FileShipper
// ---------------------------------------------------------------------------

func TestFileShipper_ShipEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	fs, err := audit.NewFileShipper(&audit.FileConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileShipper error: %v", err)
	}

	entry := &audit.LogEntry{Action: "file.test", UserID: "u2", StatusCode: 201}
	if err := fs.Ship(context.Background(), entry); err != nil {
		t.Fatalf("Ship() error: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	line := bytes.TrimRight(data, "\n")
	var decoded audit.LogEntry
	if err := json.Unmarshal(line, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Action != entry.Action {
		t.Errorf("Action = %q, want %q", decoded.Action, entry.Action)
	}
	if decoded.UserID != entry.UserID {
		t.Errorf("UserID = %q, want %q", decoded.UserID, entry.UserID)
	}
}

func TestFileShipper_MultipleEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multi.log")

	fs, _ := audit.NewFileShipper(&audit.FileConfig{Path: path})
	for i := 0; i < 5; i++ {
		fs.Ship(context.Background(), &audit.LogEntry{Action: "test", StatusCode: i})
	}
	fs.Close()

	data, _ := os.ReadFile(path)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	count := 0
	for scanner.Scan() {
		count++
	}
	if count != 5 {
		t.Errorf("file has %d lines, want 5", count)
	}
}

func TestNewFileShipper_InvalidPath(t *testing.T) {
	// Nonexistent parent directory → OpenFile should fail
	path := filepath.Join(t.TempDir(), "nodir", "audit.log")
	if _, err := audit.NewFileShipper(&audit.FileConfig{Path: path}); err == nil {
		t.Error("expected error for path with nonexistent parent, got nil")
	}
}

// ---------------------------------------------------------------------------
// WebhookShipper with batching (covers processBatches + flushBatch)
// ---------------------------------------------------------------------------

func TestWebhookShipper_BatchedShip(t *testing.T) {
	// Use a channel to synchronize: server signals when it receives a request
	done := make(chan struct{}, 10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		done <- struct{}{}
	}))
	defer srv.Close()

	ws, err := audit.NewWebhookShipper(&audit.WebhookConfig{
		URL:           srv.URL,
		Timeout:       5 * time.Second,
		BatchSize:     1, // Batch of 1 triggers flush immediately on first entry
		FlushInterval: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewWebhookShipper error: %v", err)
	}
	defer ws.Close()

	// Ship 1 entry — fills the batch immediately (BatchSize=1)
	if err := ws.Ship(context.Background(), &audit.LogEntry{Action: "batch-1"}); err != nil {
		t.Fatalf("Ship(1) error: %v", err)
	}

	// Wait for server to receive the batch (up to 3 seconds)
	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for batch to be sent to server")
	}
}

func TestWebhookShipper_BatchFlushOnInterval(t *testing.T) {
	done := make(chan struct{}, 10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		done <- struct{}{}
	}))
	defer srv.Close()

	ws, _ := audit.NewWebhookShipper(&audit.WebhookConfig{
		URL:           srv.URL,
		Timeout:       5 * time.Second,
		BatchSize:     100,                   // Large batch, won't fill by count
		FlushInterval: 50 * time.Millisecond, // Short flush interval
	})
	defer ws.Close()

	// Ship 1 entry — should be flushed by the interval ticker
	ws.Ship(context.Background(), &audit.LogEntry{Action: "interval-flush"})

	// Wait for server to receive (up to 3 seconds)
	select {
	case <-done:
		// success — interval flush worked
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for interval flush")
	}
}

func TestWebhookShipper_BatchFlushOnClose(t *testing.T) {
	done := make(chan struct{}, 10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		done <- struct{}{}
	}))
	defer srv.Close()

	ws, _ := audit.NewWebhookShipper(&audit.WebhookConfig{
		URL:           srv.URL,
		Timeout:       5 * time.Second,
		BatchSize:     100,           // Large batch, won't fill by count
		FlushInterval: 5 * time.Second, // Long interval, won't fire in test
	})

	// Ship 1 entry and wait for goroutine to add it to the batch
	ws.Ship(context.Background(), &audit.LogEntry{Action: "flush-on-close"})
	// Give goroutine time to pick up entry from batchCh and add to batch slice
	time.Sleep(50 * time.Millisecond)

	// Close triggers batch flush of remaining entries
	ws.Close()

	// Wait for server to receive (up to 3 seconds)
	select {
	case <-done:
		// success — close flushed the batch
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for close-triggered flush")
	}
}

// ---------------------------------------------------------------------------
// FileShipper rotation (covers rotate function)
// ---------------------------------------------------------------------------

func TestFileShipper_Rotate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Pre-fill file to just over 1MB to trigger rotation on next Ship call
	data := make([]byte, 1*1024*1024+1)
	if err := os.WriteFile(logPath, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fs, err := audit.NewFileShipper(&audit.FileConfig{
		Path:       logPath,
		MaxSizeMB:  1,
		MaxBackups: 2,
	})
	if err != nil {
		t.Fatalf("NewFileShipper: %v", err)
	}
	defer fs.Close()

	// This Ship call should trigger rotation because the file is > 1MB
	if err := fs.Ship(context.Background(), &audit.LogEntry{Action: "after-rotate"}); err != nil {
		t.Fatalf("Ship() error: %v", err)
	}

	// Original file should exist (new file after rotation)
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("log file missing after rotation: %v", err)
	}
	// Backup .1 should exist
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Errorf("backup .1 missing after rotation: %v", err)
	}
}
