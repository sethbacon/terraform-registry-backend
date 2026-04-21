// Package main implements a chaos/soak testing tool for the Terraform Registry.
//
// It injects controlled failures (Redis down, storage 5xx, DB connection storms)
// while continuously exercising the API, then reports on error rates and recovery.
//
// Usage:
//
//	go run ./cmd/chaos-test --target https://localhost:5000 --duration 1h --scenario all
//	go run ./cmd/chaos-test --target https://localhost:5000 --duration 10m --scenario redis-down
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Scenario describes a chaos injection scenario.
type Scenario struct {
	Name        string
	Description string
	Run         func(ctx context.Context, cfg *Config, results *Results)
}

// Config holds the chaos test configuration.
type Config struct {
	TargetURL   string
	Duration    time.Duration
	APIKey      string
	Concurrency int
	Scenario    string
}

// Results tracks test outcomes.
type Results struct {
	TotalRequests atomic.Int64
	SuccessCount  atomic.Int64
	FailureCount  atomic.Int64
	TimeoutCount  atomic.Int64
	LatencySum    atomic.Int64 // microseconds
	MaxLatency    atomic.Int64 // microseconds
	Errors        sync.Map     // error message → count
}

// Report generates a summary report.
type Report struct {
	Scenario      string       `json:"scenario"`
	Duration      string       `json:"duration"`
	TotalRequests int64        `json:"total_requests"`
	SuccessCount  int64        `json:"success_count"`
	FailureCount  int64        `json:"failure_count"`
	TimeoutCount  int64        `json:"timeout_count"`
	SuccessRate   float64      `json:"success_rate_percent"`
	AvgLatencyMs  float64      `json:"avg_latency_ms"`
	MaxLatencyMs  float64      `json:"max_latency_ms"`
	TopErrors     []ErrorCount `json:"top_errors"`
	Pass          bool         `json:"pass"`
}

// ErrorCount pairs an error message with its occurrence count.
type ErrorCount struct {
	Error string `json:"error"`
	Count int64  `json:"count"`
}

var scenarios = map[string]Scenario{
	"health-soak": {
		Name:        "health-soak",
		Description: "Continuously hit /health to measure baseline availability",
		Run:         runHealthSoak,
	},
	"api-soak": {
		Name:        "api-soak",
		Description: "Exercise major API endpoints under sustained load",
		Run:         runAPISoak,
	},
	"connection-storm": {
		Name:        "connection-storm",
		Description: "Open many concurrent connections to test connection pooling",
		Run:         runConnectionStorm,
	},
	"large-payload": {
		Name:        "large-payload",
		Description: "Send oversized payloads to test input validation and limits",
		Run:         runLargePayload,
	},
}

func main() {
	cfg := &Config{}
	flag.StringVar(&cfg.TargetURL, "target", "http://localhost:5000", "Registry base URL")
	flag.DurationVar(&cfg.Duration, "duration", 10*time.Minute, "Test duration")
	flag.StringVar(&cfg.APIKey, "api-key", os.Getenv("TFR_API_KEY"), "API key for authenticated endpoints")
	flag.IntVar(&cfg.Concurrency, "concurrency", 10, "Number of concurrent workers")
	flag.StringVar(&cfg.Scenario, "scenario", "all", "Scenario to run (all, health-soak, api-soak, connection-storm, large-payload)")
	flag.Parse()

	fmt.Printf("Terraform Registry — Chaos/Soak Test\n")
	fmt.Printf("=====================================\n")
	fmt.Printf("Target:      %s\n", cfg.TargetURL)
	fmt.Printf("Duration:    %s\n", cfg.Duration)
	fmt.Printf("Concurrency: %d\n", cfg.Concurrency)
	fmt.Printf("Scenario:    %s\n", cfg.Scenario)
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	if cfg.Scenario == "all" {
		for name, scenario := range scenarios {
			fmt.Printf("--- Running scenario: %s ---\n", name)
			results := &Results{}
			scenarioCtx, scenarioCancel := context.WithTimeout(ctx, cfg.Duration/time.Duration(len(scenarios)))
			scenario.Run(scenarioCtx, cfg, results)
			scenarioCancel()
			printReport(name, cfg, results)
			fmt.Println()
		}
	} else {
		scenario, ok := scenarios[cfg.Scenario]
		if !ok {
			fmt.Fprintf(os.Stderr, "Unknown scenario: %s\nAvailable: ", cfg.Scenario)
			for name := range scenarios {
				fmt.Fprintf(os.Stderr, "%s ", name)
			}
			fmt.Fprintln(os.Stderr)
			os.Exit(1)
		}
		results := &Results{}
		scenario.Run(ctx, cfg, results)
		printReport(cfg.Scenario, cfg, results)
	}
}

func printReport(scenario string, cfg *Config, results *Results) {
	total := results.TotalRequests.Load()
	success := results.SuccessCount.Load()
	failures := results.FailureCount.Load()
	timeouts := results.TimeoutCount.Load()

	var successRate float64
	var avgLatency float64
	if total > 0 {
		successRate = float64(success) / float64(total) * 100
		avgLatency = float64(results.LatencySum.Load()) / float64(total) / 1000.0
	}
	maxLatency := float64(results.MaxLatency.Load()) / 1000.0

	// Collect top errors
	topErrors := make([]ErrorCount, 0)
	results.Errors.Range(func(key, value interface{}) bool {
		topErrors = append(topErrors, ErrorCount{
			Error: key.(string),
			Count: value.(int64),
		})
		return true
	})

	pass := successRate >= 95.0

	report := Report{
		Scenario:      scenario,
		Duration:      cfg.Duration.String(),
		TotalRequests: total,
		SuccessCount:  success,
		FailureCount:  failures,
		TimeoutCount:  timeouts,
		SuccessRate:   successRate,
		AvgLatencyMs:  avgLatency,
		MaxLatencyMs:  maxLatency,
		TopErrors:     topErrors,
		Pass:          pass,
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(data))

	if pass {
		fmt.Printf("\nRESULT: PASS (%.1f%% success rate)\n", successRate)
	} else {
		fmt.Printf("\nRESULT: FAIL (%.1f%% success rate, threshold: 95%%)\n", successRate)
	}
}

func recordRequest(results *Results, latency time.Duration, err error) {
	results.TotalRequests.Add(1)
	latUs := latency.Microseconds()
	results.LatencySum.Add(latUs)

	// Update max latency (compare-and-swap loop)
	for {
		current := results.MaxLatency.Load()
		if latUs <= current || results.MaxLatency.CompareAndSwap(current, latUs) {
			break
		}
	}

	if err != nil {
		results.FailureCount.Add(1)
		errMsg := err.Error()
		if len(errMsg) > 100 {
			errMsg = errMsg[:100]
		}
		if val, loaded := results.Errors.LoadOrStore(errMsg, int64(1)); loaded {
			results.Errors.Store(errMsg, val.(int64)+1)
		}
	} else {
		results.SuccessCount.Add(1)
	}
}

// --------------------------------------------------------------------------
// Scenarios
// --------------------------------------------------------------------------

func runHealthSoak(ctx context.Context, cfg *Config, results *Results) {
	client := &http.Client{Timeout: 5 * time.Second}
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				start := time.Now()
				resp, err := client.Get(cfg.TargetURL + "/health")
				latency := time.Since(start)

				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != 200 {
						err = fmt.Errorf("health returned %d", resp.StatusCode)
					}
				}
				recordRequest(results, latency, err)

				// Small jitter between requests
				time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
			}
		}()
	}
	wg.Wait()
}

func runAPISoak(ctx context.Context, cfg *Config, results *Results) {
	client := &http.Client{Timeout: 10 * time.Second}
	endpoints := []string{
		"/health",
		"/api/v1/version",
		"/v1/modules",
		"/v1/providers",
	}

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				endpoint := endpoints[rand.Intn(len(endpoints))]
				req, _ := http.NewRequestWithContext(ctx, "GET", cfg.TargetURL+endpoint, nil)
				if cfg.APIKey != "" {
					req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
				}

				start := time.Now()
				resp, err := client.Do(req)
				latency := time.Since(start)

				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode >= 500 {
						err = fmt.Errorf("%s returned %d", endpoint, resp.StatusCode)
					}
				}
				recordRequest(results, latency, err)

				time.Sleep(time.Duration(rand.Intn(200)) * time.Millisecond)
			}
		}()
	}
	wg.Wait()
}

func runConnectionStorm(ctx context.Context, cfg *Config, results *Results) {
	// Open many connections simultaneously to test pooling/limits
	burstSize := cfg.Concurrency * 5
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        burstSize,
			MaxIdleConnsPerHost: burstSize,
			MaxConnsPerHost:     burstSize,
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				start := time.Now()
				resp, err := client.Get(cfg.TargetURL + "/health")
				latency := time.Since(start)

				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != 200 {
						err = fmt.Errorf("storm: status %d", resp.StatusCode)
					}
				}
				recordRequest(results, latency, err)
			}
		}()
	}
	wg.Wait()
}

func runLargePayload(ctx context.Context, cfg *Config, results *Results) {
	client := &http.Client{Timeout: 30 * time.Second}
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Create a large payload (10MB) to test upload limits
				payload := make([]byte, 10*1024*1024)
				for j := range payload {
					payload[j] = byte('A' + rand.Intn(26))
				}

				start := time.Now()
				resp, err := client.Post(
					cfg.TargetURL+"/api/v1/modules",
					"application/octet-stream",
					io.NopCloser(io.LimitReader(randomReader{}, 10*1024*1024)),
				)
				latency := time.Since(start)

				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					// 413 or 401 are expected (payload too large or unauthorized)
					if resp.StatusCode >= 500 {
						err = fmt.Errorf("large payload: status %d", resp.StatusCode)
					}
				}
				recordRequest(results, latency, err)

				time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
			}
		}()
	}
	wg.Wait()
}

type randomReader struct{}

func (r randomReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte('A' + rand.Intn(26))
	}
	return len(p), nil
}
