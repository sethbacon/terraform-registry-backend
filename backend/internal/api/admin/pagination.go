// pagination.go holds the page-window parsing this package's list endpoints
// share, and the two ways they build PaginationMeta.
//
// It exists because issue #893 was one defect copy-pasted into five handlers:
// each parsed `page`/`per_page` by hand and each collapsed an over-large
// per_page to the endpoint's DEFAULT instead of its MAXIMUM, so asking for more
// rows returned fewer. Parsing it once is what stops the sixth copy.
package admin

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/pagination"
)

// Per-endpoint page-size limits. Each pair is what the endpoint's swagger
// annotation promises, and the clamp is now the same promise in code: below the
// range you get the default, above it you get the maximum.
const (
	orgPerPageDefault = 20
	orgPerPageMax     = 100

	userPerPageDefault = 20
	userPerPageMax     = 100

	auditPerPageDefault = 25
	auditPerPageMax     = 200
)

// queryInt reads a query parameter as an int.
//
// An absent or unparseable parameter yields 0, which every pagination clamp
// resolves to the endpoint's default — so the "?per_page=lots" case needs no
// branch of its own, and cannot be given a different answer by one handler than
// by its siblings.
func queryInt(c *gin.Context, name string) int {
	n, _ := strconv.Atoi(c.Query(name))
	return n
}

// countedPage builds the pagination meta for an endpoint that has an exact
// total, deriving has_more from it so that no consumer has to.
func countedPage(page, perPage, offset, returned, total int) PaginationMeta {
	t := int64(total)
	return PaginationMeta{
		Page:    page,
		PerPage: perPage,
		HasMore: pagination.HasMore(offset, returned, total),
		Total:   &t,
	}
}

// probedPage builds the pagination meta for an endpoint with no total, where
// has_more came from pagination.Probe/Trim instead.
//
// Total stays nil: the search axes have no counting query on the identity
// store, and reporting 0 there would be a count nobody performed.
func probedPage(page, perPage int, hasMore bool) PaginationMeta {
	return PaginationMeta{Page: page, PerPage: perPage, HasMore: hasMore}
}
