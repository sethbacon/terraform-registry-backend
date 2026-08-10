package setup

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// suite-identity #153 — the first-run setup path writes the SAME four
// storage_config credential columns as the admin CRUD handlers, so it has to
// bind them the same way.
//
// This is the half of the column family that is easy to miss: a reviewer looking
// at internal/api/admin/storage.go sees every write converted and concludes the
// column is done, while a fresh install still lands unbound rows here. That is
// also why registering these columns in the backfill required both writers
// converted first — a sweep behind an unconverted writer converts rows the next
// first-run save simply re-creates unbound.

// setupStorageCredential is one encrypted column of the config the builder
// returns, paired with the context it must be bound to.
type setupStorageCredential struct {
	column  string
	secret  string
	sealed  func(*models.StorageConfig) string
	context func(string) []byte
}

var setupStorageCases = []struct {
	name        string
	input       *models.StorageConfigInput
	credentials []setupStorageCredential
}{
	{
		name: "azure",
		input: &models.StorageConfigInput{
			BackendType:        "azure",
			AzureAccountName:   "acct",
			AzureContainerName: "ctr",
			AzureAccountKey:    "dGVzdC1henVyZS1rZXk=",
		},
		credentials: []setupStorageCredential{{
			column:  "azure_account_key_encrypted",
			secret:  "dGVzdC1henVyZS1rZXk=",
			sealed:  func(c *models.StorageConfig) string { return c.AzureAccountKeyEncrypted.String },
			context: models.StorageConfigAzureAccountKeyContext,
		}},
	},
	{
		name: "s3",
		input: &models.StorageConfigInput{
			BackendType:       "s3",
			S3Bucket:          "bkt",
			S3Region:          "us-east-1",
			S3AuthMethod:      "static",
			S3AccessKeyID:     "AKIAEXAMPLEKEYID",
			S3SecretAccessKey: "wJalrXUtnFEMI-EXAMPLE-SECRET",
		},
		credentials: []setupStorageCredential{
			{
				column:  "s3_access_key_id_encrypted",
				secret:  "AKIAEXAMPLEKEYID",
				sealed:  func(c *models.StorageConfig) string { return c.S3AccessKeyIDEncrypted.String },
				context: models.StorageConfigS3AccessKeyIDContext,
			},
			{
				column:  "s3_secret_access_key_encrypted",
				secret:  "wJalrXUtnFEMI-EXAMPLE-SECRET",
				sealed:  func(c *models.StorageConfig) string { return c.S3SecretAccessKeyEncrypted.String },
				context: models.StorageConfigS3SecretAccessKeyContext,
			},
		},
	},
	{
		name: "gcs",
		input: &models.StorageConfigInput{
			BackendType:        "gcs",
			GCSBucket:          "bkt",
			GCSProjectID:       "proj",
			GCSAuthMethod:      "service_account",
			GCSCredentialsJSON: `{"type":"service_account","private_key":"-----BEGIN"}`,
		},
		credentials: []setupStorageCredential{{
			column:  "gcs_credentials_json_encrypted",
			secret:  `{"type":"service_account","private_key":"-----BEGIN"}`,
			sealed:  func(c *models.StorageConfig) string { return c.GCSCredentialsJSONEncrypted.String },
			context: models.StorageConfigGCSCredentialsJSONContext,
		}},
	},
}

// setupStorageColumns is the whole family, for the sibling-column assertions.
var setupStorageColumns = []struct {
	column  string
	context func(string) []byte
}{
	{"azure_account_key_encrypted", models.StorageConfigAzureAccountKeyContext},
	{"s3_access_key_id_encrypted", models.StorageConfigS3AccessKeyIDContext},
	{"s3_secret_access_key_encrypted", models.StorageConfigS3SecretAccessKeyContext},
	{"gcs_credentials_json_encrypted", models.StorageConfigGCSCredentialsJSONContext},
}

func TestBuildEncryptedStorageConfig_BindsCredentialsToTheRow(t *testing.T) {
	for _, sc := range setupStorageCases {
		t.Run(sc.name, func(t *testing.T) {
			env := newTestEnv(t)

			cfg, err := env.h.buildEncryptedStorageConfig(sc.input)
			if err != nil {
				t.Fatalf("buildEncryptedStorageConfig: %v", err)
			}
			// SaveStorageConfig inserts this struct verbatim, so cfg.ID is the
			// id the row will carry.
			id := cfg.ID.String()

			for _, cred := range sc.credentials {
				raw := cred.sealed(cfg)
				if raw == "" {
					t.Errorf("%s: nothing was sealed", cred.column)
					continue
				}

				got, bound, err := env.cipher.OpenWithContextOrLegacy(raw, cred.context(id))
				if err != nil {
					t.Errorf("%s: does not open under its own row context: %v", cred.column, err)
					continue
				}
				if !bound {
					t.Errorf("%s: opened only via the LEGACY path, so it was sealed WITHOUT a "+
						"context; a fresh install still writes movable credentials", cred.column)
				}
				if got != cred.secret {
					t.Errorf("%s = %q, want %q", cred.column, got, cred.secret)
				}
				if _, err := env.cipher.OpenWithContext(raw, cred.context(otherSetupConfigID)); err == nil {
					t.Errorf("%s: opened under another config's context; it could be moved "+
						"between storage configurations", cred.column)
				}
				for _, sibling := range setupStorageColumns {
					if sibling.column == cred.column {
						continue
					}
					if _, err := env.cipher.OpenWithContext(raw, sibling.context(id)); err == nil {
						t.Errorf("%s: also opened as %s of the SAME row; the two columns are "+
							"interchangeable", cred.column, sibling.column)
					}
				}
			}
		})
	}
}

const otherSetupConfigID = "99999999-9999-9999-9999-999999999999"
