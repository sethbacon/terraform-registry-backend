package services

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// suite-identity #153, read side. buildStorageFromConfig is the only consumer
// that decrypts the storage_config credential columns, so it is where a wrong or
// missing context surfaces — and it surfaces as an operator's storage migration
// failing on a credential they cannot recover, long after the change.
//
// The cases below are the four things the read has to get right, and each one
// fails if the read is written differently:
//
//	bound          -- reads the new form (fails if the context is omitted)
//	legacy         -- still reads the old form (fails if OpenWithContext is used
//	                  instead of OpenWithContextOrLegacy, which would break every
//	                  row written before the backfill)
//	other row      -- refuses a ciphertext lifted from another configuration
//	sibling column -- refuses one lifted from another column of the SAME row
//
// The last two are what make the first two more than a round-trip: the legacy
// fallback accepts any no-AAD ciphertext, so if it also accepted a bound one
// from elsewhere the binding would buy nothing.

// storageReadColumn is one encrypted column: how to place a ciphertext on the
// model, and the context the read side must use for it.
type storageReadColumn struct {
	name        string
	backendType string
	place       func(*models.StorageConfig, string)
	context     func(string) []byte
}

var storageReadColumns = []storageReadColumn{
	{
		name:        "azure_account_key_encrypted",
		backendType: "azure",
		place: func(sc *models.StorageConfig, ct string) {
			sc.AzureAccountName = sql.NullString{String: "acct", Valid: true}
			sc.AzureContainerName = sql.NullString{String: "ctr", Valid: true}
			sc.AzureAccountKeyEncrypted = sql.NullString{String: ct, Valid: true}
		},
		context: models.StorageConfigAzureAccountKeyContext,
	},
	{
		name:        "s3_access_key_id_encrypted",
		backendType: "s3",
		place: func(sc *models.StorageConfig, ct string) {
			sc.S3Bucket = sql.NullString{String: "bkt", Valid: true}
			sc.S3Region = sql.NullString{String: "us-east-1", Valid: true}
			sc.S3AccessKeyIDEncrypted = sql.NullString{String: ct, Valid: true}
		},
		context: models.StorageConfigS3AccessKeyIDContext,
	},
	{
		name:        "s3_secret_access_key_encrypted",
		backendType: "s3",
		place: func(sc *models.StorageConfig, ct string) {
			sc.S3Bucket = sql.NullString{String: "bkt", Valid: true}
			sc.S3Region = sql.NullString{String: "us-east-1", Valid: true}
			sc.S3SecretAccessKeyEncrypted = sql.NullString{String: ct, Valid: true}
		},
		context: models.StorageConfigS3SecretAccessKeyContext,
	},
	{
		name:        "gcs_credentials_json_encrypted",
		backendType: "gcs",
		place: func(sc *models.StorageConfig, ct string) {
			sc.GCSBucket = sql.NullString{String: "bkt", Valid: true}
			sc.GCSProjectID = sql.NullString{String: "proj", Valid: true}
			sc.GCSCredentialsJSONEncrypted = sql.NullString{String: ct, Valid: true}
		},
		context: models.StorageConfigGCSCredentialsJSONContext,
	},
}

// decryptFailed reports whether err came from the decrypt step rather than from
// the backend constructor.
//
// buildStorageFromConfig ends in storage.NewStorage, which needs credentials
// this test does not have and generally fails; the plaintext never escapes the
// function. The decrypt failures are the only ones this test can and should
// distinguish, and each carries its own "failed to decrypt <column>" message.
func decryptFailed(err error) bool {
	return err != nil && strings.Contains(err.Error(), "failed to decrypt")
}

func newStorageReadCipher(t *testing.T) *crypto.TokenCipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 23)
	}
	tc, err := crypto.NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

func TestBuildStorageFromConfig_ReadsBoundAndLegacyCredentials(t *testing.T) {
	tc := newStorageReadCipher(t)
	svc := NewStorageMigrationService(nil, nil, nil, nil, tc, &config.Config{})

	configID := uuid.New()
	otherID := uuid.New()

	for _, col := range storageReadColumns {
		// sibling is any other column of the same family, for the
		// move-within-one-row case.
		var sibling storageReadColumn
		for _, other := range storageReadColumns {
			if other.name != col.name {
				sibling = other
				break
			}
		}

		cases := []struct {
			name string
			// seal produces the ciphertext stored in col's column.
			seal       func() (string, error)
			wantUsable bool
		}{
			{
				name:       "bound to its own row and column",
				seal:       func() (string, error) { return tc.SealWithContext("cred", col.context(configID.String())) },
				wantUsable: true,
			},
			{
				name:       "legacy unbound ciphertext still readable",
				seal:       func() (string, error) { return tc.Seal("cred") },
				wantUsable: true,
			},
			{
				name:       "bound to a different storage config",
				seal:       func() (string, error) { return tc.SealWithContext("cred", col.context(otherID.String())) },
				wantUsable: false,
			},
			{
				name:       "bound to a sibling column of the same row",
				seal:       func() (string, error) { return tc.SealWithContext("cred", sibling.context(configID.String())) },
				wantUsable: false,
			},
		}

		for _, tt := range cases {
			t.Run(col.name+"/"+tt.name, func(t *testing.T) {
				ct, err := tt.seal()
				if err != nil {
					t.Fatalf("seal: %v", err)
				}

				sc := &models.StorageConfig{ID: configID, BackendType: col.backendType}
				col.place(sc, ct)

				_, buildErr := svc.buildStorageFromConfig(sc)
				if got := !decryptFailed(buildErr); got != tt.wantUsable {
					if tt.wantUsable {
						t.Fatalf("%s: the credential could not be decrypted: %v", col.name, buildErr)
					}
					t.Fatalf("%s: a ciphertext that does not belong to this row+column was "+
						"accepted; the binding is not enforced on read", col.name)
				}
			})
		}
	}
}
