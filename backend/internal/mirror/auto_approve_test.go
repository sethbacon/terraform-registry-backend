// auto_approve_test.go covers the auto-approve rule evaluator: each rule type,
// the any/all modes, and the parsing of the auto_approve_rules JSONB column.
package mirror

import (
	"testing"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func intPtr(i int) *int { return &i }

func rules(mode string, rs ...models.AutoApproveRule) *models.AutoApproveRules {
	return &models.AutoApproveRules{Mode: mode, Rules: rs}
}

// ---------------------------------------------------------------------------
// ParseAutoApproveRules
// ---------------------------------------------------------------------------

func TestParseAutoApproveRules(t *testing.T) {
	t.Run("nil yields no rules", func(t *testing.T) {
		got, err := ParseAutoApproveRules(nil)
		if err != nil || got != nil {
			t.Fatalf("expected (nil,nil), got (%v,%v)", got, err)
		}
	})

	t.Run("empty string yields no rules", func(t *testing.T) {
		empty := ""
		got, err := ParseAutoApproveRules(&empty)
		if err != nil || got != nil {
			t.Fatalf("expected (nil,nil), got (%v,%v)", got, err)
		}
	})

	t.Run("literal null yields no rules", func(t *testing.T) {
		null := "null"
		got, err := ParseAutoApproveRules(&null)
		if err != nil || got != nil {
			t.Fatalf("expected (nil,nil), got (%v,%v)", got, err)
		}
	})

	t.Run("valid json parses", func(t *testing.T) {
		raw := `{"rules":[{"type":"gpg_verified"},{"type":"semver_constraint","constraint":">=5.0"}],"mode":"any"}`
		got, err := ParseAutoApproveRules(&raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Mode != "any" || len(got.Rules) != 2 {
			t.Fatalf("unexpected parse result: %+v", got)
		}
		if got.Rules[1].Constraint != ">=5.0" {
			t.Fatalf("constraint not parsed: %+v", got.Rules[1])
		}
	})

	t.Run("invalid json errors", func(t *testing.T) {
		raw := `{not json`
		if _, err := ParseAutoApproveRules(&raw); err == nil {
			t.Fatal("expected error for invalid json")
		}
	})
}

// ---------------------------------------------------------------------------
// EvaluateAutoApprove — empty / nil
// ---------------------------------------------------------------------------

func TestEvaluateAutoApprove_NoRules(t *testing.T) {
	if matched, _ := EvaluateAutoApprove(nil, AutoApproveInput{Version: "1.0.0"}); matched {
		t.Fatal("nil rules should not match")
	}
	if matched, _ := EvaluateAutoApprove(rules("any"), AutoApproveInput{Version: "1.0.0"}); matched {
		t.Fatal("empty rules should not match")
	}
}

// ---------------------------------------------------------------------------
// gpg_verified
// ---------------------------------------------------------------------------

func TestEvaluateAutoApprove_GPGVerified(t *testing.T) {
	r := rules("any", models.AutoApproveRule{Type: "gpg_verified"})

	matched, rule := EvaluateAutoApprove(r, AutoApproveInput{Version: "1.0.0", GPGVerified: true})
	if !matched || rule != "gpg_verified" {
		t.Fatalf("expected gpg_verified match, got (%v,%q)", matched, rule)
	}

	if matched, _ := EvaluateAutoApprove(r, AutoApproveInput{Version: "1.0.0", GPGVerified: false}); matched {
		t.Fatal("unverified version should not match gpg_verified")
	}
}

// ---------------------------------------------------------------------------
// patch_only
// ---------------------------------------------------------------------------

func TestEvaluateAutoApprove_PatchOnly(t *testing.T) {
	r := rules("any", models.AutoApproveRule{Type: "patch_only"})

	cases := []struct {
		name     string
		version  string
		existing []string
		want     bool
	}{
		{"patch bump of highest", "5.1.3", []string{"5.1.2", "5.1.1", "5.0.9"}, true},
		{"minor bump rejected", "5.2.0", []string{"5.1.2"}, false},
		{"major bump rejected", "6.0.0", []string{"5.1.2"}, false},
		{"no existing rejected", "5.1.0", nil, false},
		{"older patch rejected", "5.1.1", []string{"5.1.2"}, false},
		{"equal rejected", "5.1.2", []string{"5.1.2"}, false},
		{"patch of highest among many minors", "5.2.4", []string{"5.2.3", "5.1.9", "4.0.0"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, _ := EvaluateAutoApprove(r, AutoApproveInput{Version: tc.version, ExistingVersions: tc.existing})
			if matched != tc.want {
				t.Fatalf("version %s existing %v: want %v got %v", tc.version, tc.existing, tc.want, matched)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// semver_constraint
// ---------------------------------------------------------------------------

func TestEvaluateAutoApprove_SemverConstraint(t *testing.T) {
	r := rules("any", models.AutoApproveRule{Type: "semver_constraint", Constraint: ">=5.0, <6.0"})

	cases := []struct {
		version string
		want    bool
	}{
		{"5.0.0", true},
		{"5.9.9", true},
		{"6.0.0", false},
		{"4.9.0", false},
	}
	for _, tc := range cases {
		matched, _ := EvaluateAutoApprove(r, AutoApproveInput{Version: tc.version})
		if matched != tc.want {
			t.Fatalf("version %s: want %v got %v", tc.version, tc.want, matched)
		}
	}

	t.Run("empty constraint never matches", func(t *testing.T) {
		bad := rules("any", models.AutoApproveRule{Type: "semver_constraint"})
		if matched, _ := EvaluateAutoApprove(bad, AutoApproveInput{Version: "5.0.0"}); matched {
			t.Fatal("empty constraint should not match")
		}
	})

	t.Run("invalid version never matches", func(t *testing.T) {
		if matched, _ := EvaluateAutoApprove(r, AutoApproveInput{Version: "not-a-version"}); matched {
			t.Fatal("invalid version should not match")
		}
	})
}

// ---------------------------------------------------------------------------
// delay_hours
// ---------------------------------------------------------------------------

func TestEvaluateAutoApprove_DelayHours(t *testing.T) {
	r := rules("any", models.AutoApproveRule{Type: "delay_hours", Hours: intPtr(24)})

	t.Run("not aged enough", func(t *testing.T) {
		if matched, _ := EvaluateAutoApprove(r, AutoApproveInput{Version: "1.0.0", VersionAge: 1 * time.Hour}); matched {
			t.Fatal("1h-old version should not pass 24h delay")
		}
	})

	t.Run("aged past delay", func(t *testing.T) {
		matched, rule := EvaluateAutoApprove(r, AutoApproveInput{Version: "1.0.0", VersionAge: 25 * time.Hour})
		if !matched || rule != "delay_hours" {
			t.Fatalf("25h-old version should pass 24h delay, got (%v,%q)", matched, rule)
		}
	})

	t.Run("missing or zero hours never matches", func(t *testing.T) {
		bad := rules("any", models.AutoApproveRule{Type: "delay_hours"})
		if matched, _ := EvaluateAutoApprove(bad, AutoApproveInput{Version: "1.0.0", VersionAge: 1000 * time.Hour}); matched {
			t.Fatal("delay_hours without hours should not match")
		}
	})
}

// ---------------------------------------------------------------------------
// modes
// ---------------------------------------------------------------------------

func TestEvaluateAutoApprove_AnyMode(t *testing.T) {
	// gpg fails, constraint matches -> any returns the constraint rule.
	r := rules("any",
		models.AutoApproveRule{Type: "gpg_verified"},
		models.AutoApproveRule{Type: "semver_constraint", Constraint: ">=5.0"},
	)
	matched, rule := EvaluateAutoApprove(r, AutoApproveInput{Version: "5.1.0", GPGVerified: false})
	if !matched || rule != "semver_constraint" {
		t.Fatalf("any mode should match on second rule, got (%v,%q)", matched, rule)
	}
}

func TestEvaluateAutoApprove_AllMode(t *testing.T) {
	r := rules("all",
		models.AutoApproveRule{Type: "gpg_verified"},
		models.AutoApproveRule{Type: "semver_constraint", Constraint: ">=5.0"},
	)

	t.Run("all match", func(t *testing.T) {
		matched, rule := EvaluateAutoApprove(r, AutoApproveInput{Version: "5.1.0", GPGVerified: true})
		if !matched || rule != "all" {
			t.Fatalf("all mode should match, got (%v,%q)", matched, rule)
		}
	})

	t.Run("one fails", func(t *testing.T) {
		if matched, _ := EvaluateAutoApprove(r, AutoApproveInput{Version: "5.1.0", GPGVerified: false}); matched {
			t.Fatal("all mode should fail when one rule fails")
		}
	})

	t.Run("empty mode defaults to any", func(t *testing.T) {
		def := rules("", models.AutoApproveRule{Type: "gpg_verified"})
		matched, rule := EvaluateAutoApprove(def, AutoApproveInput{Version: "1.0.0", GPGVerified: true})
		if !matched || rule != "gpg_verified" {
			t.Fatalf("empty mode should behave like any, got (%v,%q)", matched, rule)
		}
	})
}

// ---------------------------------------------------------------------------
// unknown rule types fail closed
// ---------------------------------------------------------------------------

func TestEvaluateAutoApprove_UnknownRule(t *testing.T) {
	t.Run("any mode skips unknown", func(t *testing.T) {
		r := rules("any", models.AutoApproveRule{Type: "made_up"})
		if matched, _ := EvaluateAutoApprove(r, AutoApproveInput{Version: "1.0.0"}); matched {
			t.Fatal("unknown rule should not match in any mode")
		}
	})

	t.Run("all mode fails on unknown", func(t *testing.T) {
		r := rules("all",
			models.AutoApproveRule{Type: "gpg_verified"},
			models.AutoApproveRule{Type: "made_up"},
		)
		if matched, _ := EvaluateAutoApprove(r, AutoApproveInput{Version: "1.0.0", GPGVerified: true}); matched {
			t.Fatal("unknown rule should fail all mode")
		}
	})
}
