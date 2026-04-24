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
//	Read operations (HEAD, GET): governed by the optional auth middleware in router.go.
//	Write operations (PUT manifest): not supported — use POST /api/v1/modules.
package oci

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
		c.JSON(statusCode, ociErrors("MANIFEST_UNKNOWN", err.Error()))
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
		c.JSON(statusCode, ociErrors("MANIFEST_UNKNOWN", err.Error()))
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
	mv, statusCode, err := h.lookupVersionByDigest(c)
	if err != nil {
		c.JSON(statusCode, ociErrors("BLOB_UNKNOWN", err.Error()))
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
	mv, statusCode, err := h.lookupVersionByDigest(c)
	if err != nil {
		c.JSON(statusCode, ociErrors("BLOB_UNKNOWN", err.Error()))
		return
	}

	rc, err := h.storage.Download(c.Request.Context(), mv.StoragePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ociErrors("BLOB_UNKNOWN", "failed to retrieve blob"))
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

	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil || org == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("cannot resolve organization")
	}

	module, err := h.moduleRepo.GetModule(c.Request.Context(), org.ID, namespace, name, system)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("internal error")
	}
	if module == nil {
		return nil, http.StatusNotFound, fmt.Errorf("module %s/%s/%s not found", namespace, name, system)
	}

	mv, err := h.moduleRepo.GetVersion(c.Request.Context(), module.ID, ref)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("internal error")
	}
	if mv == nil {
		return nil, http.StatusNotFound, fmt.Errorf("version %s not found", ref)
	}

	configData := []byte("{}")
	configDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(configData))

	manifest := ociManifest{
		SchemaVersion: 2,
		MediaType:     mediaTypeManifest,
		Config: ociDescriptor{
			MediaType: mediaTypeConfig,
			Digest:    configDigest,
			Size:      int64(len(configData)),
		},
		Layers: []ociDescriptor{{
			MediaType: mediaTypeLayer,
			Digest:    "sha256:" + mv.Checksum,
			Size:      mv.SizeBytes,
		}},
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to marshal manifest")
	}
	return data, http.StatusOK, nil
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

	org, err := h.orgRepo.GetDefaultOrganization(c.Request.Context())
	if err != nil || org == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("cannot resolve organization")
	}

	module, err := h.moduleRepo.GetModule(c.Request.Context(), org.ID, namespace, name, system)
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
