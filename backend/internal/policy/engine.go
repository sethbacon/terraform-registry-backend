// Package policy provides OPA/Rego-based policy evaluation for the Terraform Registry.
// It exposes a PolicyEngine that can evaluate arbitrary input maps against a Rego bundle
// and return a structured result indicating whether the action is allowed.
package policy

import (
	"context"
	"fmt"
	"sync"
)

// PolicyEngine evaluates module-upload (and other) inputs against a loaded Rego policy bundle.
// The zero value is valid but will always allow (engine disabled); call Load to activate it.
//
// PolicyEngine is safe for concurrent use.
type PolicyEngine struct {
	mu      sync.RWMutex
	queries []*compiledQuery // one per policy file loaded from the bundle
	enabled bool
	mode    string // "warn" | "block"
}

// NewPolicyEngine returns a new PolicyEngine configured from cfg.  If cfg.Enabled is false
// the engine is a no-op: Evaluate always returns an allowed result.
func NewPolicyEngine(cfg Config) (*PolicyEngine, error) {
	e := &PolicyEngine{
		enabled: cfg.Enabled,
		mode:    cfg.Mode,
	}
	if !cfg.Enabled || cfg.BundleURL == "" {
		return e, nil
	}
	if err := e.loadBundle(context.Background(), cfg.BundleURL); err != nil {
		return nil, fmt.Errorf("policy engine: loading bundle: %w", err)
	}
	return e, nil
}

// Evaluate runs the input map against all loaded policies and returns an aggregated result.
// If the engine is disabled or no policies are loaded, it returns an allowed result.
func (e *PolicyEngine) Evaluate(ctx context.Context, input map[string]interface{}) (PolicyResult, error) {
	e.mu.RLock()
	queries := e.queries
	enabled := e.enabled
	mode := e.mode
	e.mu.RUnlock()

	if !enabled || len(queries) == 0 {
		return PolicyResult{Allowed: true, Mode: mode}, nil
	}

	var violations []Violation
	for _, q := range queries {
		vs, err := q.evaluate(ctx, input)
		if err != nil {
			return PolicyResult{}, fmt.Errorf("policy evaluation: %w", err)
		}
		violations = append(violations, vs...)
	}

	allowed := len(violations) == 0
	return PolicyResult{
		Allowed:    allowed,
		Mode:       mode,
		Violations: violations,
	}, nil
}

// Reload fetches and recompiles the policy bundle from the configured URL.
// Safe to call concurrently with Evaluate.
func (e *PolicyEngine) Reload(ctx context.Context, bundleURL string) error {
	if err := e.loadBundle(ctx, bundleURL); err != nil {
		return err
	}
	return nil
}

// IsEnabled reports whether the engine is active.
func (e *PolicyEngine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// Mode returns the configured enforcement mode ("warn" or "block").
func (e *PolicyEngine) Mode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mode
}

// loadBundle fetches the bundle from bundleURL, parses .rego files, and replaces the
// current query set atomically.
func (e *PolicyEngine) loadBundle(ctx context.Context, bundleURL string) error {
	regoFiles, err := fetchBundle(ctx, bundleURL)
	if err != nil {
		return err
	}

	queries, err := compileBundle(regoFiles)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.queries = queries
	e.mu.Unlock()
	return nil
}
