// serve.go handles direct file serving of module archives from local storage backends.
package modules

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// ServeFileHandler handles direct file serving for local storage
// Implements: GET /v1/files/*filepath
// Only used when local storage has ServeDirectly: true
func ServeFileHandler(storageBackend storage.Storage, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get file path from URL
		filePath := c.Param("filepath")
		if filePath == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "File path is required",
			})
			return
		}

		// Remove leading slash if present
		if len(filePath) > 0 && filePath[0] == '/' {
			filePath = filePath[1:]
		}

		// Check if file exists
		exists, err := storageBackend.Exists(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check file existence",
			})
			return
		}
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "File not found",
			})
			return
		}

		// Get file metadata
		metadata, err := storageBackend.GetMetadata(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get file metadata",
			})
			return
		}

		// Download file from storage
		reader, err := storageBackend.Download(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to read file",
			})
			return
		}
		defer reader.Close()

		// Set response headers
		c.Header("Content-Type", "application/gzip")
		c.Header("Content-Disposition", "attachment")
		c.Header("X-Checksum-SHA256", metadata.Checksum)

		// Stream file to client
		c.DataFromReader(http.StatusOK, metadata.Size, "application/gzip", reader, nil)
	}
}
