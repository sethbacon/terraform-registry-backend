package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

// compiledQuery wraps a prepared OPA rego query for a single rule path.
type compiledQuery struct {
	rulePath string
	pq       rego.PreparedEvalQuery
}

// compileBundle compiles all .rego modules and returns one compiled query per deny rule
// found under the `data.registry` package.
func compileBundle(files []regoFile) ([]*compiledQuery, error) {
	if len(files) == 0 {
		return nil, nil
	}

	// Build rego.Module options for each file.
	moduleOpts := make([]func(*rego.Rego), 0, len(files)+1)
	for _, f := range files {
		moduleOpts = append(moduleOpts, rego.Module(f.name, f.source))
	}

	// We query data.registry.deny — a set of violation messages produced by deny rules.
	queryStr := "data.registry.deny"
	moduleOpts = append(moduleOpts, rego.Query(queryStr))

	prepared, err := rego.New(moduleOpts...).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compiling policy bundle: %w", err)
	}

	return []*compiledQuery{{rulePath: queryStr, pq: prepared}}, nil
}

// evaluate runs the prepared query against input and converts the results into Violations.
// The deny rule is expected to produce a set of strings (violation messages).
func (q *compiledQuery) evaluate(ctx context.Context, input map[string]interface{}) ([]Violation, error) {
	rs, err := q.pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluating %s: %w", q.rulePath, err)
	}

	var violations []Violation
	for _, result := range rs {
		for _, expr := range result.Expressions {
			switch v := expr.Value.(type) {
			case []interface{}:
				for _, item := range v {
					if msg, ok := item.(string); ok {
						violations = append(violations, Violation{Rule: q.rulePath, Message: msg})
					}
				}
			case map[string]interface{}:
				for msg := range v {
					violations = append(violations, Violation{Rule: q.rulePath, Message: msg})
				}
			}
		}
	}

	return violations, nil
}
