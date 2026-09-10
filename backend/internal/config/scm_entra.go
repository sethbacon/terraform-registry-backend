package config

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
)

// SCMConfig groups deployment-level policy about SCM providers.
type SCMConfig struct {
	Entra EntraSCMConfig `mapstructure:"entra"`
}

// EntraSCMConfig declares which Entra credential types this deployment offers
// for azuredevops providers in entra_app auth mode.
//
// WHY DECLARED RATHER THAN DETECTED. Two of the four types work anywhere
// (client_secret, certificate) and two need the hosting platform to cooperate:
// federated needs a projected token (on AKS, the workload-identity webhook),
// and managed_identity needs Azure compute with an identity endpoint. Offering
// a type the host cannot satisfy lets an admin save a provider that can never
// mint, and the failure lands later, on a sync, far from the form that caused
// it.
//
// Detection was considered and rejected as the SOURCE of truth. Passive
// environment signals cannot see the largest class of Azure compute -- an Azure
// VM or an AKS pod on the kubelet identity exposes no environment variable, so
// managed identity would read as "unknown" precisely where it works best. An
// active probe would have to dial the link-local metadata address from
// application code, which is the exact class this codebase's egress policy
// denies, and it cannot be exercised in CI. A declaration is deterministic,
// reviewable in the same values file as everything else, and testable.
//
// Detection is still used, but only to WARN (see WarnOnCredentialTypeMismatch).
type EntraSCMConfig struct {
	// CredentialTypes is the allow-list. Env: TFR_SCM_ENTRA_CREDENTIAL_TYPES
	// (comma-separated). Defaults to the two types that need no platform, so an
	// upgrade never silently starts offering something the host cannot do.
	CredentialTypes []string `mapstructure:"credential_types"`
}

// Known credential type values, mirroring internal/scm's constants. Duplicated
// rather than imported because internal/config must not depend on a package
// that imports it; ValidateEntraCredentialTypes is unit-tested against the scm
// constants so the two cannot drift silently.
const (
	entraTypeClientSecret    = "client_secret"
	entraTypeFederated       = "federated"
	entraTypeCertificate     = "certificate"
	entraTypeManagedIdentity = "managed_identity"
)

// DefaultEntraCredentialTypes is what a deployment offers when it declares
// nothing: every credential type that has ALREADY SHIPPED ungated.
//
// Not "the types that work on any host", which was the first instinct.
// federated shipped in 4.19.0 with no gate in front of it, so defaulting it off
// would take a working option away from every AKS deployment on upgrade -- a
// silent breaking change, and one whose symptom (an admin can no longer create
// or switch to federated) points nowhere near this file. An allow-list that
// removes something on upgrade is worse than one that admits a type the host
// cannot use, because the second failure is visible and immediate.
//
// managed_identity is new in this release and is therefore NOT in the default:
// nothing can regress by its absence, and it is the type most likely to be
// wrong on a non-Azure host.
func DefaultEntraCredentialTypes() []string {
	return []string{entraTypeClientSecret, entraTypeFederated, entraTypeCertificate}
}

func knownEntraCredentialTypes() []string {
	return []string{entraTypeClientSecret, entraTypeFederated, entraTypeCertificate, entraTypeManagedIdentity}
}

// OfferedEntraCredentialTypes returns the declared set, normalised, falling back
// to the default when nothing was declared.
func (c EntraSCMConfig) OfferedEntraCredentialTypes() []string {
	if len(c.CredentialTypes) == 0 {
		return DefaultEntraCredentialTypes()
	}
	out := make([]string, 0, len(c.CredentialTypes))
	seen := map[string]bool{}
	for _, t := range c.CredentialTypes {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return DefaultEntraCredentialTypes()
	}
	sort.Strings(out)
	return out
}

// Offers reports whether this deployment offers a credential type.
func (c EntraSCMConfig) Offers(credentialType string) bool {
	for _, t := range c.OfferedEntraCredentialTypes() {
		if t == credentialType {
			return true
		}
	}
	return false
}

// ValidateEntraCredentialTypes fails startup on a value that is not a known
// credential type.
//
// Fail closed rather than ignore: a typo ("certificates", "workload_identity")
// would otherwise silently narrow what the deployment offers, and the operator
// would discover it as a missing option in the admin UI with nothing to point
// at.
func (c EntraSCMConfig) ValidateEntraCredentialTypes() error {
	known := map[string]bool{}
	for _, t := range knownEntraCredentialTypes() {
		known[t] = true
	}
	var bad []string
	for _, t := range c.OfferedEntraCredentialTypes() {
		if !known[t] {
			bad = append(bad, t)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("scm.entra.credential_types: unknown value(s) %s (known: %s)",
			strings.Join(bad, ", "), strings.Join(knownEntraCredentialTypes(), ", "))
	}
	return nil
}

// WarnOnCredentialTypeMismatch logs where the declaration and the observable
// environment disagree. It never changes behaviour and never dials anything.
//
// The asymmetry is deliberate and is the honest limit of passive detection:
//   - A POSITIVE host signal with the type NOT declared is a confident warning:
//     the platform went to the trouble of projecting a token or injecting an
//     identity endpoint, and the deployment is not using it.
//   - A type declared with NO positive signal is only a hint for federated,
//     whose signal (AZURE_FEDERATED_TOKEN_FILE) is reliably present when it
//     works. For managed_identity there is deliberately NO warning: an Azure VM
//     or an AKS pod on the kubelet identity sets no environment variable at
//     all, so silence proves nothing and warning on it would cry wolf on the
//     hosts where it works best. That blind spot is the accepted cost of not
//     probing IMDS.
func (c EntraSCMConfig) WarnOnCredentialTypeMismatch(log *slog.Logger) {
	if log == nil {
		return
	}
	offered := c.OfferedEntraCredentialTypes()
	log.Info("SCM Entra credential types offered by this deployment",
		"types", strings.Join(offered, ","),
		"source", func() string {
			if len(c.CredentialTypes) == 0 {
				return "default"
			}
			return "scm.entra.credential_types"
		}())

	federatedSignal := strings.TrimSpace(os.Getenv("AZURE_FEDERATED_TOKEN_FILE")) != ""
	identityEndpoint := strings.TrimSpace(os.Getenv("IDENTITY_ENDPOINT")) != "" ||
		strings.TrimSpace(os.Getenv("MSI_ENDPOINT")) != ""

	if federatedSignal && !c.Offers(entraTypeFederated) {
		log.Warn("this host projects a workload-identity token but federated credentials are not offered",
			"signal", "AZURE_FEDERATED_TOKEN_FILE", "fix",
			"add 'federated' to TFR_SCM_ENTRA_CREDENTIAL_TYPES to let admins use it")
	}
	if identityEndpoint && !c.Offers(entraTypeManagedIdentity) {
		log.Warn("this host provides a managed-identity endpoint but managed_identity credentials are not offered",
			"signal", "IDENTITY_ENDPOINT/MSI_ENDPOINT", "fix",
			"add 'managed_identity' to TFR_SCM_ENTRA_CREDENTIAL_TYPES to let admins use it")
	}
	if c.Offers(entraTypeFederated) && !federatedSignal {
		log.Warn("federated credentials are offered but this host projects no workload-identity token",
			"signal", "AZURE_FEDERATED_TOKEN_FILE is unset", "impact",
			"an admin can save a federated provider that cannot mint here")
	}
	// Deliberately no symmetric warning for managed_identity -- see the doc
	// comment: absence of an identity endpoint variable is not evidence of
	// absence on IMDS-only Azure compute.
}
