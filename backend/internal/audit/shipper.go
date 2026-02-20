// Package audit handles structured audit log emission for security-relevant
// events such as authentication attempts, provider uploads, deletions, and
// permission changes. Audit logs are intentionally separate from application
// logs because they have different consumers and retention requirements —
// application logs are ephemeral debug output consumed by on-call engineers,
// while audit logs are immutable records consumed by security teams and may be
// subject to compliance retention policies measured in years. The package
// supports multiple simultaneous destinations (file, webhook, syslog) via the
// Shipper interface so audit records can be routed to a SIEM or log aggregator
// independently of the application's own logging pipeline.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// LogEntry represents a structured audit log entry
type LogEntry struct {
	Timestamp      time.Time              `json:"timestamp"`
	Action         string                 `json:"action"`
	UserID         string                 `json:"user_id,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	ResourceType   string                 `json:"resource_type,omitempty"`
	ResourceID     string                 `json:"resource_id,omitempty"`
	IPAddress      string                 `json:"ip_address,omitempty"`
	AuthMethod     string                 `json:"auth_method,omitempty"`
	StatusCode     int                    `json:"status_code,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Shipper defines the interface for audit log shipping
type Shipper interface {
	// Ship sends an audit log entry to the destination
	Ship(ctx context.Context, entry *LogEntry) error
	// Close cleans up any resources
	Close() error
}

// ShipperConfig holds configuration for audit log shippers
type ShipperConfig struct {
	// Enabled determines if this shipper is active
	Enabled bool `json:"enabled"`
	// Type is the shipper type (syslog, webhook, file)
	Type string `json:"type"`
	// Syslog configuration
	Syslog *SyslogConfig `json:"syslog,omitempty"`
	// Webhook configuration
	Webhook *WebhookConfig `json:"webhook,omitempty"`
	// File configuration
	File *FileConfig `json:"file,omitempty"`
}

// SyslogConfig holds syslog shipper configuration
type SyslogConfig struct {
	// Network is the syslog network type (udp, tcp, unix)
	Network string `json:"network"`
	// Address is the syslog server address
	Address string `json:"address"`
	// Tag is the syslog tag/program name
	Tag string `json:"tag"`
	// Facility is the syslog facility
	Facility string `json:"facility"`
}

// WebhookConfig holds webhook shipper configuration
type WebhookConfig struct {
	// URL is the webhook endpoint
	URL string `json:"url"`
	// Headers are additional HTTP headers to send
	Headers map[string]string `json:"headers,omitempty"`
	// Timeout is the HTTP request timeout
	Timeout time.Duration `json:"timeout"`
	// BatchSize is how many entries to batch before sending (0 = no batching)
	BatchSize int `json:"batch_size"`
	// FlushInterval is how often to flush batched entries
	FlushInterval time.Duration `json:"flush_interval"`
}

// FileConfig holds file shipper configuration
type FileConfig struct {
	// Path is the log file path
	Path string `json:"path"`
	// MaxSizeMB is the maximum file size before rotation
	MaxSizeMB int `json:"max_size_mb"`
	// MaxBackups is the number of backup files to keep
	MaxBackups int `json:"max_backups"`
}

// MultiShipper ships to multiple destinations
type MultiShipper struct {
	shippers []Shipper
	mu       sync.RWMutex
}

// NewMultiShipper creates a new multi-shipper from configs
func NewMultiShipper(configs []ShipperConfig) (*MultiShipper, error) {
	ms := &MultiShipper{
		shippers: make([]Shipper, 0),
	}

	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}

		var shipper Shipper
		var err error

		switch cfg.Type {
		case "syslog":
			// Syslog is only supported on Unix systems
			// On Windows, skip this shipper with a warning
			fmt.Printf("Warning: syslog shipper is not supported on this platform, skipping\n")
			continue
		case "webhook":
			if cfg.Webhook == nil {
				return nil, fmt.Errorf("webhook config is required for webhook shipper")
			}
			shipper, err = NewWebhookShipper(cfg.Webhook)
		case "file":
			if cfg.File == nil {
				return nil, fmt.Errorf("file config is required for file shipper")
			}
			shipper, err = NewFileShipper(cfg.File)
		default:
			return nil, fmt.Errorf("unknown shipper type: %s", cfg.Type)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create %s shipper: %w", cfg.Type, err)
		}

		ms.shippers = append(ms.shippers, shipper)
	}

	return ms, nil
}

// Ship sends an entry to all configured shippers
func (ms *MultiShipper) Ship(ctx context.Context, entry *LogEntry) error {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var lastErr error
	for _, shipper := range ms.shippers {
		if err := shipper.Ship(ctx, entry); err != nil {
			lastErr = err
			// Log error but continue to other shippers
			fmt.Printf("Audit shipper error: %v\n", err)
		}
	}
	return lastErr
}

// Close closes all shippers
func (ms *MultiShipper) Close() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	var lastErr error
	for _, shipper := range ms.shippers {
		if err := shipper.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// WebhookShipper ships audit logs to a webhook
type WebhookShipper struct {
	cfg       *WebhookConfig
	client    *http.Client
	batchCh   chan *LogEntry
	batch     []*LogEntry
	batchMu   sync.Mutex
	closeCh   chan struct{}
	closeOnce sync.Once
}

// NewWebhookShipper creates a new webhook shipper
func NewWebhookShipper(cfg *WebhookConfig) (*WebhookShipper, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	ws := &WebhookShipper{
		cfg: cfg,
		client: &http.Client{
			Timeout: timeout,
		},
		batchCh: make(chan *LogEntry, 1000),
		batch:   make([]*LogEntry, 0),
		closeCh: make(chan struct{}),
	}

	// Start batch processor if batching is enabled
	if cfg.BatchSize > 0 {
		go ws.processBatches()
	}

	return ws, nil
}

// processBatches handles batched sending
func (ws *WebhookShipper) processBatches() {
	flushInterval := ws.cfg.FlushInterval
	if flushInterval == 0 {
		flushInterval = 5 * time.Second
	}

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case entry := <-ws.batchCh:
			ws.batchMu.Lock()
			ws.batch = append(ws.batch, entry)
			if len(ws.batch) >= ws.cfg.BatchSize {
				ws.flushBatch()
			}
			ws.batchMu.Unlock()
		case <-ticker.C:
			ws.batchMu.Lock()
			if len(ws.batch) > 0 {
				ws.flushBatch()
			}
			ws.batchMu.Unlock()
		case <-ws.closeCh:
			// Flush remaining
			ws.batchMu.Lock()
			if len(ws.batch) > 0 {
				ws.flushBatch()
			}
			ws.batchMu.Unlock()
			return
		}
	}
}

// flushBatch sends the current batch
func (ws *WebhookShipper) flushBatch() {
	if len(ws.batch) == 0 {
		return
	}

	data, err := json.Marshal(ws.batch)
	if err != nil {
		fmt.Printf("Failed to marshal audit batch: %v\n", err)
		ws.batch = ws.batch[:0]
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), ws.cfg.Timeout)
	defer cancel()

	if err := ws.sendRequest(ctx, data); err != nil {
		fmt.Printf("Failed to send audit batch: %v\n", err)
	}

	ws.batch = ws.batch[:0]
}

// Ship sends an entry to the webhook
func (ws *WebhookShipper) Ship(ctx context.Context, entry *LogEntry) error {
	// If batching is enabled, queue the entry
	if ws.cfg.BatchSize > 0 {
		select {
		case ws.batchCh <- entry:
			return nil
		default:
			// Channel full, send directly
		}
	}

	// Send directly
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	return ws.sendRequest(ctx, data)
}

// sendRequest sends the HTTP request
func (ws *WebhookShipper) sendRequest(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", ws.cfg.URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range ws.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := ws.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// Close closes the webhook shipper
func (ws *WebhookShipper) Close() error {
	ws.closeOnce.Do(func() {
		close(ws.closeCh)
	})
	return nil
}

// FileShipper ships audit logs to a file
type FileShipper struct {
	cfg  *FileConfig
	file *os.File
	mu   sync.Mutex
}

// NewFileShipper creates a new file shipper
func NewFileShipper(cfg *FileConfig) (*FileShipper, error) {
	file, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &FileShipper{
		cfg:  cfg,
		file: file,
	}, nil
}

// Ship writes an entry to the file
func (fs *FileShipper) Ship(ctx context.Context, entry *LogEntry) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Check file size for rotation
	if fs.cfg.MaxSizeMB > 0 {
		info, err := fs.file.Stat()
		if err == nil && info.Size() > int64(fs.cfg.MaxSizeMB)*1024*1024 {
			if err := fs.rotate(); err != nil {
				fmt.Printf("Failed to rotate audit log: %v\n", err)
			}
		}
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	// Write with newline
	if _, err := fs.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write audit entry: %w", err)
	}

	return nil
}

// rotate rotates the log file
func (fs *FileShipper) rotate() error {
	// Close current file
	if err := fs.file.Close(); err != nil {
		return err
	}

	// Rotate existing backups
	for i := fs.cfg.MaxBackups - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", fs.cfg.Path, i)
		newPath := fmt.Sprintf("%s.%d", fs.cfg.Path, i+1)
		_ = os.Rename(oldPath, newPath)
	}

	// Rename current to .1
	_ = os.Rename(fs.cfg.Path, fs.cfg.Path+".1")

	// Remove oldest if needed
	if fs.cfg.MaxBackups > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", fs.cfg.Path, fs.cfg.MaxBackups+1))
	}

	// Open new file
	file, err := os.OpenFile(fs.cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	fs.file = file
	return nil
}

// Close closes the file
func (fs *FileShipper) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.file.Close()
}
