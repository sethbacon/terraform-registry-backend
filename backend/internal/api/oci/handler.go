// Package oci implements the OCI Distribution Spec v1.1 endpoints for the Terraform Registry.
// It exposes module archives as OCI artifacts so that tools like `oras` can pull modules.
//
// Image naming convention:
//
//	/v2/<namespace>/<name>/<system>/manifests/<version>   — manifest (module metadata)
//	/v2/<namespace>/<name>/<system>/blobs/sha256:<digest> — blob (tar.gz archive)
//
// Media types:
//
//	Config layer: application/vnd.oci.image.config.v1+json
//	Module layer: application/vnd.opentofu.modulepkg.v1.tar+gzip
//
// Authentication:
//
//	Read operations (HEAD, GET) and write operations (PUT manifest) have no authentication
//	or authorization middleware applied to the /v2 route group in router.go — this surface is
//	fully public by design, consistent with the module/provider download protocol. PUT manifest
//	is a stub that always returns 405 (see PutManifest), so it cannot be used for unauthenticated writes.
package oci

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

const (
	mediaTypeConfig   = "application/vnd.oci.image.config.v1+json"
	mediaTypeLayer    = "application/vnd.opentofu.modulepkg.v1.tar+gzip"
	mediaTypeManifest = "application/vnd.oci.image.manifest.v1+json"
	ociSpecVersion    = "2"
)

// Handler serves OCI Distribution Spec v1.1 endpoints backed by the registry's module store.
type Handler struct {
	moduleRepo *repositories.ModuleRepository
	orgRepo    *repositories.OrganizationRepository
	storage    storage.Storage
}

// NewHandler creates a new OCI Handler.
func NewHandler(db *sql.DB, storageBackend storage.Storage) *Handler {
	return &Handler{
		moduleRepo: repositories.NewModuleRepository(db),
		orgRepo:    repositories.NewOrganizationRepository(db),
		storage:    storageBackend,
	}
}

// Ping handles GET /v2/ — OCI capability discovery.
//
// @Summary      OCI API ping
// @Description  Returns 200 to indicate OCI Distribution Spec v1.1 support.
// @Tags         System
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /v2/ [get]
func (h *Handler) Ping(c *gin.Context) {
	c.Header("OCI-Distribution-Spec-Version", ociSpecVersion)
	// Docker Registry v2 API version header — conventionally checked by
	// existing OCI/Docker Registry v2 tooling (oras, crane, containerd/distribution
	// clients) during /v2/ capability probing.
	c.Header("Docker-Distribution-Api-Version", "registry/2.0")
	c.JSON(http.StatusOK, gin.H{})
}

// HeadManifest handles HEAD /v2/<namespace>/<name>/<system>/manifests/<reference>.
//
// @Summary      Check module manifest
// @Description  Returns headers for the OCI manifest corresponding to a module version.
// @Tags         Modules
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Provider/system"
// @Param        reference  path  string  true  "Version tag or digest"
// @Success      200
// @Failure      404  {object}  map[string]interface{}
// @Router       /v2/{namespace}/{name}/{system}/manifests/{reference} [head]
func (h *Handler) HeadManifest(c *gin.Context) {
	data, statusCode, err := h.buildManifestJSON(c)
	if err != nil {
		c.JSON(statusCode, ociErrors(ociErrorCode(statusCode, "MANIFEST_UNKNOWN"), err.Error()))
		return
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	c.Header("Content-Type", mediaTypeManifest)
	c.Header("Docker-Content-Digest", digest)
	c.Header("Content-Length", fmt.Sprintf("%d", len(data)))
	c.Status(http.StatusOK)
}

// GetManifest handles GET /v2/<namespace>/<name>/<system>/manifests/<reference>.
//
// @Summary      Get module manifest
// @Description  Returns the OCI manifest for a module version.
// @Tags         Modules
// @Produce      json
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Provider/system"
// @Param        reference  path  string  true  "Version tag or digest"
// @Success      200  {object}  ociManifest
// @Failure      404  {object}  map[string]interface{}
// @Router       /v2/{namespace}/{name}/{system}/manifests/{reference} [get]
func (h *Handler) GetManifest(c *gin.Context) {
	data, statusCode, err := h.buildManifestJSON(c)
	if err != nil {
		c.JSON(statusCode, ociErrors(ociErrorCode(statusCode, "MANIFEST_UNKNOWN"), err.Error()))
		return
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	c.Header("Docker-Content-Digest", digest)
	c.Data(http.StatusOK, mediaTypeManifest, data)
}

// HeadBlob handles HEAD /v2/<namespace>/<name>/<system>/blobs/<digest>.
//
// @Summary      Check module blob
// @Description  Returns headers for the module archive blob identified by its digest.
// @Tags         Modules
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Provider/system"
// @Param        digest     path  string  true  "Blob digest (sha256:...)"
// @Success      200
// @Failure      404  {object}  map[string]interface{}
// @Router       /v2/{namespace}/{name}/{system}/blobs/{digest} [head]
func (h *Handler) HeadBlob(c *gin.Context) {
	// Same constant config blob as GetBlob: a HEAD that 404s on an object GET
	// serves is its own inconsistency, and OCI clients HEAD before pulling.
	if c.Param("digest") == ociConfigDigest() {
		c.Header("Docker-Content-Digest", ociConfigDigest())
		c.Header("Content-Length", fmt.Sprintf("%d", len(ociConfigBlob)))
		c.Header("Content-Type", mediaTypeConfig)
		c.Status(http.StatusOK)
		return
	}

	mv, statusCode, err := h.lookupVersionByDigest(c)
	if err != nil {
		c.JSON(statusCode, ociErrors(ociErrorCode(statusCode, "BLOB_UNKNOWN"), err.Error()))
		return
	}
	c.Header("Content-Type", mediaTypeLayer)
	c.Header("Content-Length", fmt.Sprintf("%d", mv.SizeBytes))
	c.Header("Docker-Content-Digest", "sha256:"+mv.Checksum)
	c.Status(http.StatusOK)
}

// GetBlob handles GET /v2/<namespace>/<name>/<system>/blobs/<digest>.
//
// @Summary      Download module blob
// @Description  Streams the module archive (tar.gz) for the given digest.
// @Tags         Modules
// @Produce      application/octet-stream
// @Param        namespace  path  string  true  "Module namespace"
// @Param        name       path  string  true  "Module name"
// @Param        system     path  string  true  "Provider/system"
// @Param        digest     path  string  true  "Blob digest (sha256:...)"
// @Success      200
// @Failure      404  {object}  map[string]interface{}
// @Router       /v2/{namespace}/{name}/{system}/blobs/{digest} [get]
func (h *Handler) GetBlob(c *gin.Context) {
	// The config blob every manifest advertises (issue #755). It is a constant,
	// not a stored object, so it never appears in module_versions.checksum and
	// the archive lookup below can never find it -- a client pulling the config
	// descriptor this server just handed it got BLOB_UNKNOWN.
	if c.Param("digest") == ociConfigDigest() {
		c.Header("Docker-Content-Digest", ociConfigDigest())
		c.Data(http.StatusOK, mediaTypeConfig, ociConfigBlob)
		return
	}

	mv, statusCode, err := h.lookupVersionByDigest(c)
	if err != nil {
		c.JSON(statusCode, ociErrors(ociErrorCode(statusCode, "BLOB_UNKNOWN"), err.Error()))
		return
	}

	rc, err := h.storage.Download(c.Request.Context(), mv.StoragePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ociErrors("UNKNOWN", "failed to retrieve blob"))
		return
	}
	defer rc.Close() //nolint:errcheck

	c.Header("Content-Type", mediaTypeLayer)
	c.Header("Content-Length", fmt.Sprintf("%d", mv.SizeBytes))
	c.Header("Docker-Content-Digest", "sha256:"+mv.Checksum)
	c.Status(http.StatusOK)
	_, _ = io.Copy(c.Writer, rc)
}

// PutManifest handles PUT /v2/<namespace>/<name>/<system>/manifests/<reference>.
// OCI push is not supported; use the upload API instead.
//
// @Summary      Push module manifest (not supported)
// @Description  OCI push is not supported; use POST /api/v1/modules to publish modules.
// @Tags         Modules
// @Security     Bearer
// @Produce      json
// @Failure      405  {object}  map[string]interface{}
// @Router       /v2/{namespace}/{name}/{system}/manifests/{reference} [put]
func (h *Handler) PutManifest(c *gin.Context) {
	// RFC 7231 §6.5.5 requires a 405 response to list the supported methods.
	c.Header("Allow", "GET, HEAD")
	c.JSON(http.StatusMethodNotAllowed, ociErrors("UNSUPPORTED",
		"OCI push is not supported; use POST /api/v1/modules to publish modules"))
}

// ─── manifest building ────────────────────────────────────────────────────────

// ociManifest is a minimal OCI image manifest (schemaVersion 2).
type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

// ociDescriptor is an OCI content descriptor.
type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// buildManifestJSON resolves the module version from path params and returns serialised manifest JSON.
func (h *Handler) buildManifestJSON(c *gin.Context) ([]byte, int, error) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")
	ref := c.Param("reference")

	// Resolved by namespace, with no organization. The OCI path is
	// /v2/:namespace/:name/:system/... — three identifier segments, the same
	// grammar as the Terraform protocol, with nowhere for a client to name an
	// organization. Ownership lives on the namespace claim and governs pushing,
	// not pulling.
	module, _, err := h.moduleRepo.GetModuleByNamespace(c.Request.Context(), namespace, name, system)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("internal error")
	}
	if module == nil {
		return nil, http.StatusNotFound, fmt.Errorf("module %s/%s/%s not found", namespace, name, system)
	}

	var mv *models.ModuleVersion
	if strings.HasPrefix(ref, "sha256:") {
		// By content digest, as the OCI spec requires (issue #755).
		versions, lErr := h.moduleRepo.ListVersions(c.Request.Context(), module.ID)
		if lErr != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("internal error")
		}
		mv = manifestByDigest(versions, ref)
	} else {
		var gErr error
		mv, gErr = h.moduleRepo.GetVersion(c.Request.Context(), module.ID, ref)
		if gErr != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("internal error")
		}
	}
	if mv == nil {
		return nil, http.StatusNotFound, fmt.Errorf("manifest %s not found", ref)
	}

	data, err := marshalManifest(mv)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to marshal manifest")
	}
	return data, http.StatusOK, nil
}

// ociConfigBlob is the manifest's config object.
//
// It is a constant: the manifest carries no image configuration, so every
// manifest this registry serves advertises the digest of "{}". GetBlob serves
// it (issue #755) -- before that, the config descriptor named a blob that could
// never be fetched, because blob resolution matches the module ARCHIVE
// checksum and no archive hashes to sha256("{}"). An OCI client that pulls the
// config, as verification flows do, got BLOB_UNKNOWN for a descriptor this
// server had just handed it.
var ociConfigBlob = []byte("{}")

// ociConfigDigest is sha256("{}") = 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a.
func ociConfigDigest() string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(ociConfigBlob))
}

// marshalManifest renders the manifest for a version.
//
// Pure in mv: the bytes depend only on the layer checksum and size, which is
// what makes resolving a manifest BY DIGEST possible without storing the digest
// or adding a column -- see manifestByDigest.
func marshalManifest(mv *models.ModuleVersion) ([]byte, error) {
	manifest := ociManifest{
		SchemaVersion: 2,
		MediaType:     mediaTypeManifest,
		Config: ociDescriptor{
			MediaType: mediaTypeConfig,
			Digest:    ociConfigDigest(),
			Size:      int64(len(ociConfigBlob)),
		},
		Layers: []ociDescriptor{{
			MediaType: mediaTypeLayer,
			Digest:    "sha256:" + mv.Checksum,
			Size:      mv.SizeBytes,
		}},
	}
	return json.Marshal(manifest)
}

// manifestByDigest finds the version whose manifest hashes to digest.
//
// The OCI Distribution Spec requires a manifest to be fetchable by its own
// content digest, not only by tag, and standard tooling relies on it for
// pinned/verified pulls. Every reference used to go to GetVersion, whose query
// is `WHERE version = $2` against the semver column, so a "sha256:..."
// reference could never match a row and always returned MANIFEST_UNKNOWN --
// including the exact digest this server returned in Docker-Content-Digest a
// moment earlier (issue #755).
//
// It resolves by RECOMPUTING rather than by lookup, deliberately. The issue's
// own recommendation was to route the reference through GetVersionByChecksum,
// the path GetBlob uses; that column holds the tar.gz ARCHIVE checksum, which
// is a different value from the manifest digest. Taking that advice would make
// a digest space no client is ever given resolve, while the digest clients
// actually hold kept 404ing -- the reported bug, still there, now harder to see.
//
// Since marshalManifest is pure in the version row, the digest is derivable
// from data already in hand, so this needs no new column and no migration.
func manifestByDigest(versions []*models.ModuleVersion, digest string) *models.ModuleVersion {
	for _, mv := range versions {
		data, err := marshalManifest(mv)
		if err != nil {
			continue
		}
		if fmt.Sprintf("sha256:%x", sha256.Sum256(data)) == digest {
			return mv
		}
	}
	return nil
}

// lookupVersionByDigest resolves a module version from path params + digest.
func (h *Handler) lookupVersionByDigest(c *gin.Context) (*versionBlob, int, error) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	system := c.Param("system")
	digestParam := c.Param("digest") // e.g. "sha256:abc123"

	const prefix = "sha256:"
	if len(digestParam) <= len(prefix) || digestParam[:len(prefix)] != prefix {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid digest format; expected sha256:<hex>")
	}
	checksum := digestParam[len(prefix):]

	// Resolved by namespace, with no organization. The OCI path is
	// /v2/:namespace/:name/:system/... — three identifier segments, the same
	// grammar as the Terraform protocol, with nowhere for a client to name an
	// organization. Ownership lives on the namespace claim and governs pushing,
	// not pulling.
	module, _, err := h.moduleRepo.GetModuleByNamespace(c.Request.Context(), namespace, name, system)
	if err != nil || module == nil {
		return nil, http.StatusNotFound, fmt.Errorf("module not found")
	}

	mv, err := h.moduleRepo.GetVersionByChecksum(c.Request.Context(), module.ID, checksum)
	if err != nil || mv == nil {
		return nil, http.StatusNotFound, fmt.Errorf("blob not found")
	}

	return &versionBlob{
		StoragePath: mv.StoragePath,
		SizeBytes:   mv.SizeBytes,
		Checksum:    mv.Checksum,
	}, http.StatusOK, nil
}

// versionBlob holds the fields needed to serve a module archive.
type versionBlob struct {
	StoragePath string
	SizeBytes   int64
	Checksum    string
}

// ociErrors returns the standard OCI error body format.
func ociErrors(code, message string) gin.H {
	return gin.H{"errors": []gin.H{{"code": code, "message": message}}}
}

// ociErrorCode picks the OCI error code for a failed lookup: notFoundCode
// (e.g. MANIFEST_UNKNOWN/BLOB_UNKNOWN) for genuine 4xx "does not exist"
// responses, but the OCI-registered generic "UNKNOWN" code for 5xx internal
// failures — reusing the not-found code there would misrepresent a
// transient/retryable server fault as permanent absence.
func ociErrorCode(statusCode int, notFoundCode string) string {
	if statusCode >= http.StatusInternalServerError {
		return "UNKNOWN"
	}
	return notFoundCode
}
