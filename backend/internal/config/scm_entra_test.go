package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// The default must contain every credential type that has ALREADY SHIPPED
// ungated. federated shipped in 4.19.0 with nothing in front of it, so
// defaulting it off would take a working option away from every AKS deployment
// on upgrade -- a silent breaking change whose symptom points nowhere near the
// config layer.
func TestDefaultEntraCredentialTypes_PreservesEveryShippedType(t *testing.T) {
	got := map[string]bool{}
	for _, t := range DefaultEntraCredentialTypes() {
		got[t] = true
	}
	for _, want := range []string{"client_secret", "federated", "certificate"} {
		if !got[want] {
			t.Errorf("%s shipped ungated and is missing from the default; upgrading would "+
				"remove a working option from existing deployments", want)
		}
	}
	// managed_identity is new in this release: nothing can regress by its
	// absence, and it is the type most likely to be wrong on a non-Azure host.
	if got["managed_identity"] {
		t.Error("managed_identity is on by default; a non-Azure deployment would offer an " +
			"option that can never mint")
	}
}

func TestEntraSCMConfig_OffersAndNormalisation(t *testing.T) {
	t.Run("an empty declaration falls back to the default", func(t *testing.T) {
		for _, c := range []EntraSCMConfig{{}, {CredentialTypes: []string{}}, {CredentialTypes: []string{"", "  "}}} {
			if !c.Offers("federated") || c.Offers("managed_identity") {
				t.Errorf("%+v did not fall back to the default set", c.CredentialTypes)
			}
		}
	})

	t.Run("case and whitespace are normalised, duplicates collapse", func(t *testing.T) {
		c := EntraSCMConfig{CredentialTypes: []string{" Managed_Identity ", "MANAGED_IDENTITY", "client_secret"}}
		got := c.OfferedEntraCredentialTypes()
		if len(got) != 2 {
			t.Fatalf("offered = %v, want 2 entries", got)
		}
		if !c.Offers("managed_identity") || !c.Offers("client_secret") {
			t.Errorf("offered = %v", got)
		}
	})

	t.Run("a declaration REPLACES the default rather than adding to it", func(t *testing.T) {
		// The whole point of an allow-list: naming one type must not leave the
		// others silently enabled.
		c := EntraSCMConfig{CredentialTypes: []string{"managed_identity"}}
		if c.Offers("client_secret") || c.Offers("federated") || c.Offers("certificate") {
			t.Errorf("declaring managed_identity left other types offered: %v",
				c.OfferedEntraCredentialTypes())
		}
	})
}

// A typo would otherwise silently narrow what the deployment offers, and the
// operator would find it as a missing option in the admin UI with nothing to
// point at.
func TestEntraSCMConfig_ValidateFailsClosedOnATypo(t *testing.T) {
	for _, bad := range [][]string{
		{"certificates"}, {"workload_identity"}, {"client_secret", "managedidentity"},
	} {
		c := EntraSCMConfig{CredentialTypes: bad}
		err := c.ValidateEntraCredentialTypes()
		if err == nil {
			t.Errorf("%v validated", bad)
			continue
		}
		if !strings.Contains(err.Error(), "scm.entra.credential_types") {
			t.Errorf("error does not name the config key: %v", err)
		}
	}
	for _, good := range [][]string{
		nil, {"client_secret"}, {"client_secret", "federated", "certificate", "managed_identity"},
	} {
		if err := (EntraSCMConfig{CredentialTypes: good}).ValidateEntraCredentialTypes(); err != nil {
			t.Errorf("%v was rejected: %v", good, err)
		}
	}
}

func TestWarnOnCredentialTypeMismatch(t *testing.T) {
	capture := func(c EntraSCMConfig, env map[string]string) string {
		var buf bytes.Buffer
		for k, v := range env {
			t.Setenv(k, v)
		}
		c.WarnOnCredentialTypeMismatch(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		return buf.String()
	}

	t.Run("a positive host signal for an undeclared type warns", func(t *testing.T) {
		out := capture(EntraSCMConfig{CredentialTypes: []string{"client_secret"}},
			map[string]string{"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/token", "IDENTITY_ENDPOINT": "", "MSI_ENDPOINT": ""})
		if !strings.Contains(out, "projects a workload-identity token") {
			t.Errorf("no warning for a projected token with federated undeclared: %s", out)
		}
		out = capture(EntraSCMConfig{CredentialTypes: []string{"client_secret"}},
			map[string]string{"AZURE_FEDERATED_TOKEN_FILE": "", "IDENTITY_ENDPOINT": "http://localhost:42/msi", "MSI_ENDPOINT": ""})
		if !strings.Contains(out, "managed-identity endpoint") {
			t.Errorf("no warning for an identity endpoint with managed_identity undeclared: %s", out)
		}
	})

	t.Run("federated declared without its signal warns", func(t *testing.T) {
		out := capture(EntraSCMConfig{CredentialTypes: []string{"federated"}},
			map[string]string{"AZURE_FEDERATED_TOKEN_FILE": "", "IDENTITY_ENDPOINT": "", "MSI_ENDPOINT": ""})
		if !strings.Contains(out, "projects no workload-identity token") {
			t.Errorf("no warning for federated declared with no projected token: %s", out)
		}
	})

	// The deliberate asymmetry, and the honest limit of passive detection: an
	// Azure VM or an AKS pod on the kubelet identity sets NO environment
	// variable, so silence proves nothing. Warning here would fire on every
	// host where managed identity works best.
	t.Run("managed_identity declared without a signal does NOT warn", func(t *testing.T) {
		out := capture(EntraSCMConfig{CredentialTypes: []string{"managed_identity"}},
			map[string]string{"AZURE_FEDERATED_TOKEN_FILE": "", "IDENTITY_ENDPOINT": "", "MSI_ENDPOINT": ""})
		if strings.Contains(out, "level=WARN") {
			t.Errorf("warned about managed_identity on a host that sets no variable; "+
				"IMDS-only Azure compute looks exactly like this: %s", out)
		}
	})

	t.Run("it always reports what is offered, and never panics on a nil logger", func(t *testing.T) {
		out := capture(EntraSCMConfig{}, map[string]string{"AZURE_FEDERATED_TOKEN_FILE": "", "IDENTITY_ENDPOINT": "", "MSI_ENDPOINT": ""})
		if !strings.Contains(out, "credential types offered") {
			t.Errorf("startup did not report the offered set: %s", out)
		}
		EntraSCMConfig{}.WarnOnCredentialTypeMismatch(nil)
	})
}
