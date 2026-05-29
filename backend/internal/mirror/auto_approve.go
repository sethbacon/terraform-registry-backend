// auto_approve.go implements the auto-approve rule evaluation for the version
// approval gate. When a mirror config has requires_approval = true, newly
// synced versions are normally held in pending_approval. Auto-approve rules
// let operators express "approve this class of version automatically" so only
// the versions that genuinely need review reach an administrator.
//
// The evaluator is pure: callers (the sync job and the delay-hours sweep) pass
// everything it needs via AutoApproveInput and act on the decision. delay_hours
// is the only time-dependent rule — at sync time VersionAge is ~0 so it never
// matches immediately; the background sweep re-evaluates aged pending versions.
package mirror

import (
	"encoding/json"
	"time"

	goversion "github.com/hashicorp/go-version"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// AutoApproveInput is everything the evaluator needs to decide a single version.
type AutoApproveInput struct {
	Version          string        // candidate version string (e.g. "5.31.0")
	GPGVerified      bool          // whether the sync GPG-verified this version
	ExistingVersions []string      // already-mirrored version strings (for patch_only)
	VersionAge       time.Duration // time since the version was synced (for delay_hours)
}

// ParseAutoApproveRules parses a mirror config's auto_approve_rules JSONB column.
// A nil or empty raw value yields (nil, nil): no rules configured.
func ParseAutoApproveRules(raw *string) (*models.AutoApproveRules, error) {
	if raw == nil || *raw == "" || *raw == "null" {
		return nil, nil
	}
	var rules models.AutoApproveRules
	if err := json.Unmarshal([]byte(*raw), &rules); err != nil {
		return nil, err
	}
	return &rules, nil
}

// EvaluateAutoApprove decides whether a pending version should be auto-approved.
// It returns matched=true with the name of the rule that authorised approval.
//
// Mode "any" (the default) approves on the first matching rule and returns that
// rule's type. Mode "all" requires every rule to match and returns "all".
// Unknown rule types never match (fail closed).
func EvaluateAutoApprove(rules *models.AutoApproveRules, in AutoApproveInput) (matched bool, rule string) {
	if rules == nil || len(rules.Rules) == 0 {
		return false, ""
	}

	mode := rules.Mode
	if mode == "" {
		mode = "any"
	}

	for _, r := range rules.Rules {
		ok := evalRule(r, in)
		switch mode {
		case "all":
			if !ok {
				return false, ""
			}
		default: // "any"
			if ok {
				return true, r.Type
			}
		}
	}

	if mode == "all" {
		return true, "all"
	}
	return false, ""
}

// evalRule evaluates a single rule against the input.
func evalRule(r models.AutoApproveRule, in AutoApproveInput) bool {
	switch r.Type {
	case "gpg_verified":
		return in.GPGVerified
	case "patch_only":
		return isPatchBump(in.Version, in.ExistingVersions)
	case "semver_constraint":
		return matchesConstraint(in.Version, r.Constraint)
	case "delay_hours":
		if r.Hours == nil || *r.Hours <= 0 {
			return false
		}
		return in.VersionAge >= time.Duration(*r.Hours)*time.Hour
	default:
		return false
	}
}

// isPatchBump reports whether version is a patch-level increment of the highest
// existing version sharing its major.minor line. With no existing versions there
// is nothing to be a patch of, so it returns false.
func isPatchBump(version string, existing []string) bool {
	cand, err := goversion.NewVersion(version)
	if err != nil {
		return false
	}
	candSeg := cand.Segments()

	var highest *goversion.Version
	for _, e := range existing {
		ev, err := goversion.NewVersion(e)
		if err != nil {
			continue
		}
		if ev.Equal(cand) {
			continue // the candidate itself
		}
		if highest == nil || ev.GreaterThan(highest) {
			highest = ev
		}
	}
	if highest == nil {
		return false
	}

	hSeg := highest.Segments()
	// Same major.minor, and the candidate is strictly newer (a higher patch).
	return candSeg[0] == hSeg[0] && candSeg[1] == hSeg[1] && cand.GreaterThan(highest)
}

// matchesConstraint reports whether version satisfies the given go-version
// constraint string (e.g. ">=5.0, <6.0").
func matchesConstraint(version, constraint string) bool {
	if constraint == "" {
		return false
	}
	v, err := goversion.NewVersion(version)
	if err != nil {
		return false
	}
	c, err := goversion.NewConstraint(constraint)
	if err != nil {
		return false
	}
	return c.Check(v)
}
