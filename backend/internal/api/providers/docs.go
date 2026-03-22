// docs.go implements provider documentation endpoints that serve cached doc metadata
// from the database and proxy doc content from the upstream registry's v2 API.
package providers

import (
	"database/sql"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// ProviderDocEntryResponse represents a single doc entry in list responses.
type ProviderDocEntryResponse struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Slug        string  `json:"slug"`
	Category    string  `json:"category"`
	Subcategory *string `json:"subcategory,omitempty"`
	Language    string  `json:"language"`
}

// ProviderDocsListResponse is returned by the doc listing endpoint.
type ProviderDocsListResponse struct {
	Docs       []ProviderDocEntryResponse `json:"docs"`
	Categories []string                   `json:"categories"`
}

// ProviderDocContentResponse is returned by the doc content endpoint.
type ProviderDocContentResponse struct {
	Content  string `json:"content"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Slug     string `json:"slug"`
}

// docCacheEntry holds a cached doc content response.
type docCacheEntry struct {
	content   string
	fetchedAt time.Time
}

// docContentCache is a simple in-memory LRU-ish cache with TTL eviction.
type docContentCache struct {
	mu      sync.RWMutex
	entries map[string]docCacheEntry
	maxSize int
	ttl     time.Duration
}

func newDocContentCache(maxSize int, ttl time.Duration) *docContentCache {
	return &docContentCache{
		entries: make(map[string]docCacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (c *docContentCache) get(key string) (string, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Since(entry.fetchedAt) > c.ttl {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return "", false
	}
	return entry.content, true
}

func (c *docContentCache) set(key, content string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Simple eviction: if at capacity, drop the oldest entry.
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range c.entries {
			if oldestKey == "" || v.fetchedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.fetchedAt
			}
		}
		delete(c.entries, oldestKey)
	}
	c.entries[key] = docCacheEntry{content: content, fetchedAt: time.Now()}
}

// @Summary      List provider documentation
// @Description  Returns documentation metadata (title, slug, category) for a specific provider version. Only available for mirrored providers whose doc index was fetched during sync.
// @Tags         Providers
// @Produce      json
// @Param        namespace  path   string  true  "Provider namespace"
// @Param        type       path   string  true  "Provider type"
// @Param        version    path   string  true  "Provider version"
// @Param        category   query  string  false "Filter by doc category (overview, resources, data-sources, etc.)"
// @Param        language   query  string  false "Filter by language (hcl, python, typescript)"
// @Success      200  {object}  ProviderDocsListResponse
// @Failure      404  {object}  map[string]interface{}  "Provider or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/{namespace}/{type}/versions/{version}/docs [get]
func ListProviderDocsHandler(db *sql.DB) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)
	docsRepo := repositories.NewProviderDocsRepository(db)

	return func(c *gin.Context) {
		namespace := c.Param("namespace")
		providerType := c.Param("type")
		version := c.Param("version")

		// Look up provider then version
		provider, err := providerRepo.GetProviderByNamespaceType(c.Request.Context(), "", namespace, providerType)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to look up provider"})
			return
		}
		if provider == nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Provider not found"})
			return
		}

		versionRecord, err := providerRepo.GetVersion(c.Request.Context(), provider.ID, version)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to look up provider version"})
			return
		}
		if versionRecord == nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Provider version not found"})
			return
		}

		// Optional filters
		var category, language *string
		if cat := c.Query("category"); cat != "" {
			category = &cat
		}
		if lang := c.Query("language"); lang != "" {
			language = &lang
		}

		docs, err := docsRepo.ListProviderVersionDocs(c.Request.Context(), versionRecord.ID, category, language)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to list documentation"})
			return
		}

		// Build response
		resp := ProviderDocsListResponse{
			Docs:       make([]ProviderDocEntryResponse, 0, len(docs)),
			Categories: []string{},
		}
		categorySet := make(map[string]bool)
		for _, d := range docs {
			resp.Docs = append(resp.Docs, ProviderDocEntryResponse{
				ID:          d.UpstreamDocID,
				Title:       d.Title,
				Slug:        d.Slug,
				Category:    d.Category,
				Subcategory: d.Subcategory,
				Language:    d.Language,
			})
			if !categorySet[d.Category] {
				categorySet[d.Category] = true
				resp.Categories = append(resp.Categories, d.Category)
			}
		}

		c.JSON(http.StatusOK, resp)
	}
}

// @Summary      Get provider documentation content
// @Description  Returns the full markdown content for a single documentation page, proxied from the upstream registry. Results are cached in memory for 15 minutes.
// @Tags         Providers
// @Produce      json
// @Param        namespace  path  string  true  "Provider namespace"
// @Param        type       path  string  true  "Provider type"
// @Param        version    path  string  true  "Provider version"
// @Param        category   path  string  true  "Documentation category (overview, resources, data-sources, etc.)"
// @Param        slug       path  string  true  "Documentation slug"
// @Success      200  {object}  ProviderDocContentResponse
// @Failure      404  {object}  map[string]interface{}  "Documentation not found"
// @Failure      502  {object}  map[string]interface{}  "Failed to fetch from upstream"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers/{namespace}/{type}/versions/{version}/docs/{category}/{slug} [get]
func GetProviderDocContentHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)
	docsRepo := repositories.NewProviderDocsRepository(db)
	cache := newDocContentCache(500, 15*time.Minute)

	return func(c *gin.Context) {
		namespace := c.Param("namespace")
		providerType := c.Param("type")
		version := c.Param("version")
		category := c.Param("category")
		slug := c.Param("slug")

		// Look up provider then version
		provider, err := providerRepo.GetProviderByNamespaceType(c.Request.Context(), "", namespace, providerType)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to look up provider"})
			return
		}
		if provider == nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Provider not found"})
			return
		}

		versionRecord, err := providerRepo.GetVersion(c.Request.Context(), provider.ID, version)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to look up provider version"})
			return
		}
		if versionRecord == nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Provider version not found"})
			return
		}

		// Look up the doc entry to get the upstream doc ID
		doc, err := docsRepo.GetProviderVersionDocBySlug(c.Request.Context(), versionRecord.ID, category, slug)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to look up documentation entry"})
			return
		}
		if doc == nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Documentation page not found"})
			return
		}

		// Check cache
		cacheKey := doc.UpstreamDocID
		if content, ok := cache.get(cacheKey); ok {
			c.JSON(http.StatusOK, ProviderDocContentResponse{
				Content:  content,
				Title:    doc.Title,
				Category: doc.Category,
				Slug:     doc.Slug,
			})
			return
		}

		// Proxy from upstream registry
		upstreamURL := "https://registry.terraform.io"
		upstream := mirror.NewUpstreamRegistry(upstreamURL)

		content, err := upstream.GetProviderDocContent(c.Request.Context(), doc.UpstreamDocID)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"status": "error", "message": "Failed to fetch documentation from upstream registry"})
			return
		}

		// Cache the result
		cache.set(cacheKey, content)

		c.JSON(http.StatusOK, ProviderDocContentResponse{
			Content:  content,
			Title:    doc.Title,
			Category: doc.Category,
			Slug:     doc.Slug,
		})
	}
}
