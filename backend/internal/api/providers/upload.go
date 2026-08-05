// upload.go implements the provider binary upload, checksum validation, and platform registration endpoint for the providers package.
package providers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
	"github.com/terraform-registry/terraform-registry/internal/tenantscope"
	"github.com/terraform-registry/terraform-registry/internal/validation"
	"github.com/terraform-registry/terraform-registry/pkg/checksum"
)

const (
	// MaxProviderBinarySize is the maximum size for a provider binary (500MB)
	MaxProviderBinarySize = 500 << 20 // 500MB

	// MaxSignatureFileSize bounds the SHA256SUMS file (~5KB) and its detached
	// signature (~1KB) generously. Anything larger is malformed.
	MaxSignatureFileSize = 64 << 10 // 64KB
)

// @Summary      Upload provider version
// @Description  Uploads a new provider version binary and associated files. Provider identity (namespace, type, version, os, arch) is supplied as multipart form fields, not path params. Requires providers:write scope. If the registry has providers.require_signing enabled, gpg_public_key, shasums_file, and shasums_signature_file become mandatory for a version's first platform upload.
// @Tags         Providers
// @Security     Bearer
// @Accept       multipart/form-data
// @Produce      json
// @Param        namespace      formData  string  true   "Provider namespace"
// @Param        type           formData  string  true   "Provider type (e.g. aws, azurerm)"
// @Param        version        formData  string  true   "Semantic version (e.g. 1.2.3)"
// @Param        os             formData  string  true   "Target OS (e.g. linux, darwin, windows)"
// @Param        arch           formData  string  true   "Target architecture (e.g. amd64, arm64)"
// @Param        protocols      formData  string  false  "JSON array of supported protocols (default [\"5.0\"])"
// @Param        gpg_public_key formData  string  false  "ASCII-armored GPG public key for signing verification"
// @Param        description    formData  string  false  "Provider description"
// @Param        source         formData  string  false  "Source URL"
// @Param        file           formData  file    true   "Provider binary (.zip, max 500MB)"
// @Param        shasums_file           formData  file    false  "SHA256SUMS file (max 64KB). Required if shasums_signature_file is provided."
// @Param        shasums_signature_file formData  file    false  "Detached GPG signature of SHA256SUMS (max 64KB). Requires shasums_file AND gpg_public_key; verified before persistence."
// @Success      201
// @Failure      400  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Failure      409  {object}  map[string]interface{}
// @Failure      500  {object}  map[string]interface{}
// @Router       /api/v1/providers [post]
// UploadHandler handles provider upload requests
// Implements: POST /api/v1/providers
// Accepts multipart form with: namespace, type, version, os, arch, protocols, gpg_public_key, file
func UploadHandler(db *sql.DB, storageBackend storage.Storage, cfg *config.Config) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		// Parse multipart form (max 500MB for provider binaries)
		if err := c.Request.ParseMultipartForm(MaxProviderBinarySize); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to parse multipart form",
			})
			return
		}

		// Get form values
		namespace := c.PostForm("namespace")
		providerType := c.PostForm("type")
		version := c.PostForm("version")
		targetOS := c.PostForm("os")
		arch := c.PostForm("arch")
		protocolsStr := c.PostForm("protocols")
		gpgPublicKey := c.PostForm("gpg_public_key")
		description := c.PostForm("description")
		source := c.PostForm("source")

		// Validate required fields
		if namespace == "" || providerType == "" || version == "" || targetOS == "" || arch == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Missing required fields: namespace, type, version, os, arch",
			})
			return
		}

		// Registry protocol paths are built from these segments — validate them the
		// same way module upload does, so unvalidated identifiers never reach the
		// DB or the storage key builder.
		for field, val := range map[string]string{"namespace": namespace, "type": providerType} {
			if err := validation.ValidateRegistrySegment(val); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf("Invalid %s: %v", field, err),
				})
				return
			}
		}

		// Validate semantic versioning
		if err := validation.ValidateSemver(version); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid version format: %v", err),
			})
			return
		}

		// Validate platform (OS/arch combination)
		if err := validation.ValidatePlatform(targetOS, arch); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid platform: %v", err),
			})
			return
		}

		// Parse protocols JSON array
		var protocols []string
		if protocolsStr != "" {
			if err := json.Unmarshal([]byte(protocolsStr), &protocols); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf("Invalid protocols format (must be JSON array): %v", err),
				})
				return
			}
		} else {
			// Default to protocol 5.0 if not specified
			protocols = []string{"5.0"}
		}

		// Validate GPG public key format if provided
		if gpgPublicKey != "" {
			if err := validation.ParseGPGPublicKey(gpgPublicKey); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf("Invalid GPG public key: %v", err),
				})
				return
			}
			// Normalize the key
			gpgPublicKey = validation.NormalizeGPGKey(gpgPublicKey)
		}

		// Read and verify the optional shasums_file / shasums_signature_file
		// multipart fields up front, before anything is written to storage or
		// the database. This lets the providers.require_signing policy gate
		// below (issue #658) reject an unsigned or invalid-signature publish
		// before a version row is ever created — previously this validation
		// happened after providerRepo.CreateVersion, so a rejected request
		// still left a permanent unsigned version row behind.
		sumsBytes, sigBytes, sumsProvided, sigProvided, sigErr := readSignatureUpload(c, gpgPublicKey)
		if sigErr != nil {
			// readSignatureUpload has already written the HTTP error.
			return
		}

		// Get uploaded file
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Missing or invalid file upload",
			})
			return
		}
		defer file.Close()

		// Write uploaded file to a temp file to avoid holding up to 500MB in memory
		tmpFile, err := os.CreateTemp("", "provider-upload-*.zip")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create temporary file",
			})
			return
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		size, err := io.Copy(tmpFile, file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to read uploaded file",
			})
			return
		}

		// Validate provider binary: check size and read ZIP magic bytes from temp file
		if size == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid provider binary: provider binary cannot be empty",
			})
			return
		}
		if size > MaxProviderBinarySize {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid provider binary: provider binary too large: %d bytes (max %d bytes)", size, MaxProviderBinarySize),
			})
			return
		}
		// Check ZIP magic bytes from the beginning of the file
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to process uploaded file",
			})
			return
		}
		magic := make([]byte, 4)
		if _, err := io.ReadFull(tmpFile, magic); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid provider binary: provider binary too small to be a valid ZIP file",
			})
			return
		}
		// #nosec G602 -- magic is guaranteed 4 bytes by io.ReadFull which only succeeds when exactly n bytes are read
		if (magic[0] != 0x50 || magic[1] != 0x4B || magic[2] != 0x03 || magic[3] != 0x04) &&
			(magic[0] != 0x50 || magic[1] != 0x4B || magic[2] != 0x05 || magic[3] != 0x06) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid provider binary: provider binary is not a valid ZIP file",
			})
			return
		}

		// Calculate SHA256 checksum (seek back to start)
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to process uploaded file",
			})
			return
		}
		sha256sum, err := checksum.CalculateSHA256(tmpFile)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to calculate checksum",
			})
			return
		}

		// GUARD namespace-create-owner-org (issue #778): the provider row is
		// stamped with the organization this upload was AUTHORIZED against.
		//
		// This route's nsAuthz.RequirePublishAccessFromForm guard resolves the
		// namespace's owning organization — the existing owner, or the
		// organization it just claimed an unowned namespace for — checks the
		// caller against it, and publishes it as owner_org_id. Reaching for
		// GetDefaultOrganization instead meant the organization the route
		// authorized and the organization the row landed in were two
		// independent values: an uploader holding providers:write in
		// organization O published a provider owned by the DEFAULT
		// organization, which they need no membership in, and the existence
		// check below looked for the provider in that same wrong organization,
		// so an upload into an existing provider created a second row instead
		// of adding a version to the first.
		//
		// The default-organization fallback survives only where no guard
		// published an owner. On this route that is the platform-admin path
		// through authorizeNamespaceMutation's ambiguous-ownership branch: a
		// request with an empty namespace is rejected above before reaching
		// here, so every non-admin upload that gets this far carries an owner.
		orgID := tenantscope.OwnerOrg(c)
		if orgID == "" {
			org, err := orgRepo.GetDefaultOrganization(c.Request.Context())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to get organization context",
				})
				return
			}
			if org == nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Default organization not found",
				})
				return
			}
			orgID = org.ID
		}

		// Check if provider already exists, create if not
		provider, err := providerRepo.GetProvider(c.Request.Context(), orgID, namespace, providerType)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query provider",
			})
			return
		}

		if provider == nil {
			// Create new provider
			provider = &models.Provider{
				OrganizationID: orgID,
				Namespace:      namespace,
				Type:           providerType,
			}
			if description != "" {
				provider.Description = &description
			}
			if source != "" {
				provider.Source = &source
			}
			// Set created_by for audit tracking
			if userID, exists := c.Get("user_id"); exists {
				if uid, ok := userID.(string); ok {
					provider.CreatedBy = &uid
				}
			}

			if err := providerRepo.CreateProvider(c.Request.Context(), provider); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to create provider: %v", err),
				})
				return
			}
		} else {
			// Update existing provider metadata if provided
			if description != "" {
				provider.Description = &description
			}
			if source != "" {
				provider.Source = &source
			}
			if err := providerRepo.UpdateProvider(c.Request.Context(), provider); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to update provider",
				})
				return
			}
		}

		// Check if version already exists, create if not
		providerVersion, err := providerRepo.GetVersion(c.Request.Context(), provider.ID, version)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query provider version",
			})
			return
		}

		// Admin-configurable signing policy (issue #658): when enabled, a
		// version publish is only accepted once it carries a GPG-verified
		// shasums_signature_file — either supplied and verified by this very
		// request (sigProvided, verified above by readSignatureUpload) or
		// already persisted on the version from a prior platform upload
		// (ShasumSignatureStorageKey). This is checked BEFORE
		// providerRepo.CreateVersion runs so a rejected request never leaves
		// a version row behind; later platform uploads for an
		// already-signed version may omit the signing fields entirely.
		alreadySigned := providerVersion != nil && providerVersion.ShasumSignatureStorageKey != nil
		if cfg.Providers.RequireSigning && !alreadySigned && !sigProvided {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "This registry requires signed provider publishes: gpg_public_key, shasums_file, and shasums_signature_file are required (providers.require_signing)",
			})
			return
		}

		// A version that is already signed (ShasumSignatureStorageKey set from
		// a prior upload) must not have its SHA256SUMS content silently
		// replaced by a bare shasums_file re-upload with no accompanying,
		// verified shasums_signature_file: storage paths are deterministic
		// (persistSignatureFiles below), so that re-upload would overwrite
		// the existing SUMS blob in place while shasum_signature_storage_key
		// keeps pointing at the old .sig file — the version would keep
		// *looking* signed (both storage-key columns still set) even though
		// the SUMS content backing that signature had changed with no
		// verification at all. Left unchecked, this silently undoes the
		// require_signing guarantee that a version, once signed, stays
		// properly signed. Reject unless this same request also supplies a
		// verified shasums_signature_file (persistSignatureFiles then
		// overwrites both files together, atomically re-establishing a
		// matching pair).
		if alreadySigned && sumsProvided && !sigProvided {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "this provider version is already signed: re-uploading shasums_file requires a matching, GPG-verified shasums_signature_file in the same request",
			})
			return
		}

		if providerVersion == nil {
			// Create new version. ShasumURL/ShasumSignatureURL stay empty here —
			// they're populated by the mirror sync path for mirrored providers.
			// For uploaded providers, the SHA256SUMS file and detached signature
			// are stored in our own backend and surfaced via the storage-key
			// columns populated below.
			providerVersion = &models.ProviderVersion{
				ProviderID:   provider.ID,
				Version:      version,
				Protocols:    protocols,
				GPGPublicKey: gpgPublicKey,
			}
			// Set published_by for audit tracking
			if userID, exists := c.Get("user_id"); exists {
				if uid, ok := userID.(string); ok {
					providerVersion.PublishedBy = &uid
				}
			}

			if err := providerRepo.CreateVersion(c.Request.Context(), providerVersion); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to create provider version: %v", err),
				})
				return
			}
		} else if sigProvided && gpgPublicKey != "" && gpgPublicKey != providerVersion.GPGPublicKey {
			// The version already exists (e.g. an earlier platform upload for
			// it, or an earlier unsigned attempt). Persist a newly supplied
			// GPG key so it isn't silently dropped: without this, a later
			// signed request could satisfy the require_signing gate above
			// (via ShasumSignatureStorageKey) while gpg_public_key stayed
			// empty forever, since it was previously only ever set inside
			// this "create new version" branch (issue #658).
			//
			// Gated on sigProvided: readSignatureUpload has already verified
			// (above) that THIS gpgPublicKey signed the shasums_file supplied
			// in THIS same request. Without that gate, any authenticated
			// upload could overwrite the persisted key with an unverified
			// value — including on a version that is already signed
			// (alreadySigned above lets the require_signing gate pass on this
			// request regardless), desyncing the advertised signing_keys
			// entry from the key that actually produced SHA256SUMS.sig.
			if err := providerRepo.UpdateVersionGPGKey(c.Request.Context(), providerVersion.ID, gpgPublicKey); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to update provider version GPG key: %v", err),
				})
				return
			}
			providerVersion.GPGPublicKey = gpgPublicKey
		}

		// Persist the already-validated shasums_file / shasums_signature_file
		// bytes read by readSignatureUpload above. These are per-version
		// files, so we only need to store them once. Subsequent platform
		// uploads against the same version can omit them; if provided, we'll
		// overwrite (the operator may be re-uploading the signed files after
		// a key rotation).
		if storeErr := persistSignatureFiles(c, storageBackend, providerRepo, providerVersion, namespace, providerType, version, sumsBytes, sigBytes, sumsProvided, sigProvided); storeErr != nil {
			// persistSignatureFiles has already written the HTTP error.
			return
		}

		// Check for duplicate platform
		existingPlatform, err := providerRepo.GetPlatform(c.Request.Context(), providerVersion.ID, targetOS, arch)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check for existing platform",
			})
			return
		}
		if existingPlatform != nil {
			c.JSON(http.StatusConflict, gin.H{
				"error": fmt.Sprintf("Platform %s/%s already exists for version %s", targetOS, arch, version),
			})
			return
		}

		// Generate storage path: providers/{namespace}/{type}/{version}/{os}_{arch}.zip
		storagePath := fmt.Sprintf("providers/%s/%s/%s/%s_%s.zip", namespace, providerType, version, targetOS, arch)

		// Seek back to start for storage upload
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to process uploaded file",
			})
			return
		}

		// Upload to storage backend
		uploadResult, err := storageBackend.Upload(
			c.Request.Context(),
			storagePath,
			tmpFile,
			size,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to upload file: %v", err),
			})
			return
		}

		// Create platform record
		platform := &models.ProviderPlatform{
			ProviderVersionID: providerVersion.ID,
			OS:                targetOS,
			Arch:              arch,
			Filename:          header.Filename,
			StoragePath:       uploadResult.Path,
			StorageBackend:    cfg.Storage.DefaultBackend,
			SizeBytes:         uploadResult.Size,
			Shasum:            sha256sum,
		}

		// Compute the h1: dirhash from the already-spooled temp file so the
		// network mirror protocol can serve the preferred hash scheme without
		// reloading the binary from storage.
		if h1, err := checksum.HashZipFile(tmpFile, size); err != nil {
			slog.Warn("failed to compute h1: hash for uploaded provider binary; zh: will be used as fallback",
				"provider", fmt.Sprintf("%s/%s@%s %s/%s", namespace, providerType, version, targetOS, arch),
				"error", err)
		} else {
			platform.H1Hash = &h1
		}

		if err := providerRepo.CreatePlatform(c.Request.Context(), platform); err != nil {
			// Try to clean up uploaded file
			if delErr := storageBackend.Delete(c.Request.Context(), uploadResult.Path); delErr != nil {
				slog.Error("failed to clean up orphaned storage artifact", // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
					"path", uploadResult.Path, "error", delErr)
			}

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create platform record",
			})
			return
		}

		// Emit publish metric
		telemetry.ProviderPublishesTotal.WithLabelValues(provider.Namespace, provider.Type).Inc()

		// Return success response with provider metadata
		c.JSON(http.StatusCreated, gin.H{
			"id":         provider.ID,
			"namespace":  provider.Namespace,
			"type":       provider.Type,
			"version":    providerVersion.Version,
			"os":         platform.OS,
			"arch":       platform.Arch,
			"protocols":  providerVersion.Protocols,
			"checksum":   platform.Shasum,
			"size_bytes": platform.SizeBytes,
			"filename":   header.Filename,
		})
	}
}

// readSignatureUpload reads the optional shasums_file and
// shasums_signature_file multipart inputs and, when a signature is supplied,
// verifies it — all before anything is written to storage or the database.
// Splitting this validation out from persistSignatureFiles (below) lets
// UploadHandler evaluate the providers.require_signing policy gate (issue
// #658) before providerRepo.CreateVersion runs.
//
//   - If neither file is provided, returns (nil, nil, false, false, nil).
//   - If shasums_signature_file is provided, shasums_file AND a non-empty
//     gpg_public_key form value are required; the signature is verified
//     against the SUMS (rejected with 400 on failure).
//   - If only shasums_file is provided (no signature), no verification is
//     needed.
//
// On any error this function writes the HTTP response and returns a non-nil
// error so the caller can abort the upload flow.
func readSignatureUpload(c *gin.Context, gpgPublicKey string) (sumsBytes, sigBytes []byte, sumsProvided, sigProvided bool, err error) {
	sumsBytes, sumsProvided, err = readOptionalMultipartFile(c, "shasums_file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, nil, false, false, err
	}
	sigBytes, sigProvided, err = readOptionalMultipartFile(c, "shasums_signature_file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, nil, false, false, err
	}

	if !sumsProvided && !sigProvided {
		return nil, nil, false, false, nil
	}

	if sigProvided {
		if !sumsProvided {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "shasums_signature_file requires shasums_file in the same upload",
			})
			return nil, nil, false, false, fmt.Errorf("sig without sums")
		}
		if gpgPublicKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "shasums_signature_file requires gpg_public_key to verify the signature",
			})
			return nil, nil, false, false, fmt.Errorf("sig without gpg key")
		}
		if verifyErr := validation.VerifySignature(gpgPublicKey, sumsBytes, sigBytes); verifyErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("shasums signature failed GPG verification: %v", verifyErr),
			})
			return nil, nil, false, false, verifyErr
		}
	}

	return sumsBytes, sigBytes, sumsProvided, sigProvided, nil
}

// persistSignatureFiles uploads the already-validated shasums_file /
// shasums_signature_file bytes returned by readSignatureUpload (above) to
// storage and records their storage keys on providerVersion:
// coverage:skip:integration-only — performs storage backend uploads and DB writes that require a live storage service; parameter validation and error paths are exercised by unit tests (TestUploadHandler_Rejects* and TestUploadHandler_StoresShasumsFileWithoutSignature).
//
// On success the version row's storage-key columns are updated and the
// download handler will start returning pre-signed URLs for these files.
// On any error this function writes the HTTP response and returns a
// non-nil error so the caller can abort the upload flow.
func persistSignatureFiles(
	c *gin.Context,
	storageBackend storage.Storage,
	providerRepo *repositories.ProviderRepository,
	providerVersion *models.ProviderVersion,
	namespace, providerType, version string,
	sumsBytes, sigBytes []byte,
	sumsProvided, sigProvided bool,
) error {
	if !sumsProvided && !sigProvided {
		return nil
	}

	// Storage paths are deterministic per version (providers/{ns}/{type}/{ver}/SHA256SUMS[.sig]),
	// so a re-upload (e.g. a key rotation on an already-signed version)
	// overwrites the existing blob in place rather than creating a new one.
	// Record whether each key was already persisted *before* this call so
	// cleanup below never deletes a blob a pre-existing DB row still
	// references: only paths genuinely new to this call may be removed on
	// failure (issue #685).
	hadExistingSumsKey := providerVersion.ShasumStorageKey != nil
	hadExistingSigKey := providerVersion.ShasumSignatureStorageKey != nil

	var sumsKey, sigKey *string

	// cleanupUploaded deletes whichever of sumsKey/sigKey this call already
	// wrote to storage, mirroring the main upload path's cleanup (~lines 300,
	// 401): a later failure in this function must not leave an orphaned blob
	// with no corresponding storage-key column (issue #685). A key that
	// already pointed at a pre-existing, DB-referenced blob is left alone —
	// deleting it here would destroy a previously-working signed version
	// whose row was never touched (the UPDATE that would have repointed it
	// is exactly what failed).
	cleanupUploaded := func() {
		if sumsKey != nil && !hadExistingSumsKey {
			if delErr := storageBackend.Delete(c.Request.Context(), *sumsKey); delErr != nil {
				slog.Error("failed to clean up orphaned storage artifact", // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
					"path", *sumsKey, "error", delErr)
			}
		}
		if sigKey != nil && !hadExistingSigKey {
			if delErr := storageBackend.Delete(c.Request.Context(), *sigKey); delErr != nil {
				slog.Error("failed to clean up orphaned storage artifact", // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
					"path", *sigKey, "error", delErr)
			}
		}
	}

	if sumsProvided {
		path := fmt.Sprintf("providers/%s/%s/%s/SHA256SUMS", namespace, providerType, version)
		if _, upErr := storageBackend.Upload(c.Request.Context(), path, bytes.NewReader(sumsBytes), int64(len(sumsBytes))); upErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to upload SHA256SUMS: %v", upErr),
			})
			return upErr
		}
		sumsKey = &path
	}

	if sigProvided {
		path := fmt.Sprintf("providers/%s/%s/%s/SHA256SUMS.sig", namespace, providerType, version)
		if _, upErr := storageBackend.Upload(c.Request.Context(), path, bytes.NewReader(sigBytes), int64(len(sigBytes))); upErr != nil {
			cleanupUploaded()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to upload SHA256SUMS signature: %v", upErr),
			})
			return upErr
		}
		sigKey = &path
	}

	if updErr := providerRepo.UpdateVersionSignatureStorage(c.Request.Context(), providerVersion.ID, sumsKey, sigKey); updErr != nil {
		cleanupUploaded()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to persist signature storage keys: %v", updErr),
		})
		return updErr
	}
	// Mirror the new values back onto the in-memory version so callers see
	// the persisted state without reloading from the DB.
	if sumsKey != nil {
		providerVersion.ShasumStorageKey = sumsKey
	}
	if sigKey != nil {
		providerVersion.ShasumSignatureStorageKey = sigKey
	}
	return nil
}

// readOptionalMultipartFile reads up to MaxSignatureFileSize bytes from the
// named multipart file. Returns (nil, false, nil) when the field is absent
// (the common case for platform uploads that don't include SUMS data).
// Returns an error when the field exists but is malformed or oversized.
func readOptionalMultipartFile(c *gin.Context, field string) ([]byte, bool, error) {
	file, header, err := c.Request.FormFile(field)
	if err == http.ErrMissingFile {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("invalid %s field: %w", field, err)
	}
	defer file.Close()

	if header.Size > MaxSignatureFileSize {
		return nil, true, fmt.Errorf("%s exceeds %d-byte limit", field, MaxSignatureFileSize)
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxSignatureFileSize+1))
	if err != nil {
		return nil, true, fmt.Errorf("failed to read %s: %w", field, err)
	}
	if int64(len(data)) > MaxSignatureFileSize {
		return nil, true, fmt.Errorf("%s exceeds %d-byte limit", field, MaxSignatureFileSize)
	}
	return data, true, nil
}
