package models

// Additional-authenticated-data contexts for the storage-backend credentials
// held at rest in storage_config.
//
// Each binds a ciphertext to the row AND the column it belongs to, so a sealed
// credential cannot be lifted out of one storage configuration and written into
// another — or into a different credential column of its own row — by anyone
// with database write access. Without a context, GCM authenticates that move
// happily, because nothing in the ciphertext says where it belongs
// (suite-identity #153).
//
// They live here, next to the StorageConfig they describe, because this column
// family has FOUR call sites in three packages: the admin CRUD handlers
// (internal/api/admin) and the first-run setup path (internal/api/setup) both
// write it, internal/services reads it when building a migration's source or
// target backend, and internal/maintenance re-seals it during the backfill. A
// hand-built string in four places drifts in one of them, and the failure
// surfaces as "failed to decrypt s3 secret access key" during a storage
// migration — long after the change that caused it, against a credential only
// an operator can restore.
//
// The id is the canonical text form of storage_config.id (uuid.UUID.String(),
// which is what lib/pq also yields when the column is scanned into a string).
// A string rather than a uuid.UUID so the backfill registry, which reads ids as
// text out of the database, calls the SAME function the application seals with
// rather than a parallel one that can disagree.
//
// Four functions rather than one taking a column name: the compiler then checks
// the pairing, and a read site cannot silently ask for the wrong column's
// context. Distinct contexts WITHIN a row matter here as much as between rows —
// an S3 access key id and its secret access key live in the same row, and a
// row-level context alone would let the pair be swapped and still authenticate.
//
// Changing a returned format is a breaking change for stored data: every
// already-bound ciphertext stops opening. It would need the same treatment the
// original adoption gets — a transition read that accepts both, then a backfill.

// storageConfigContext builds one column's context. The column suffix is the
// literal database column name, so the binding is legible in a hex dump of the
// AAD and cannot collide with a differently-named column.
func storageConfigContext(configID, column string) []byte {
	return []byte("storage_config:" + configID + ":" + column)
}

// StorageConfigAzureAccountKeyContext binds an Azure account key to its row.
func StorageConfigAzureAccountKeyContext(configID string) []byte {
	return storageConfigContext(configID, "azure_account_key_encrypted")
}

// StorageConfigS3AccessKeyIDContext binds an S3 access key id to its row.
func StorageConfigS3AccessKeyIDContext(configID string) []byte {
	return storageConfigContext(configID, "s3_access_key_id_encrypted")
}

// StorageConfigS3SecretAccessKeyContext binds an S3 secret access key to its
// row.
//
// Deliberately distinct from StorageConfigS3AccessKeyIDContext for the SAME
// row: the two halves of one credential pair are stored side by side, and
// without the column in the context the secret could be written into the
// access-key-id column of its own row, or the reverse, and still decrypt.
func StorageConfigS3SecretAccessKeyContext(configID string) []byte {
	return storageConfigContext(configID, "s3_secret_access_key_encrypted")
}

// StorageConfigGCSCredentialsJSONContext binds a GCS service-account JSON key
// to its row.
func StorageConfigGCSCredentialsJSONContext(configID string) []byte {
	return storageConfigContext(configID, "gcs_credentials_json_encrypted")
}

// OIDCConfigClientSecretContext binds an OIDC provider's client secret to its
// row in oidc_config.
//
// The row is the unit that matters here even though only one config is active at
// a time: oidc_config holds every configuration ever saved, active or not, and
// without a binding a secret could be moved from a retired row onto the active
// one — which is a way to make the service authenticate to an issuer of
// someone else's choosing without ever touching the setup API.
//
// It lives here rather than in the identity module, unlike notify.TargetContext,
// because the identity module performs no cryptography on this column: it stores
// and returns ClientSecretCiphertext opaquely, and both the seal (the setup
// wizard) and the open (router startup) are this service's own code.
func OIDCConfigClientSecretContext(configID string) []byte {
	return []byte("oidc_config:" + configID + ":client_secret_encrypted")
}
