// Package pagination resolves the page parameters a caller supplies into the
// window a handler actually reads, and answers the one question a paginated
// response has to answer honestly: is this the whole list?
//
// It exists because of a defect shape that had been copy-pasted across nine
// handlers (issue #893):
//
//	if perPage < 1 || perPage > 100 {
//		perPage = 20
//	}
//
// Both out-of-range directions collapse to the DEFAULT. For "less than one"
// that is right. For "more than the maximum" it is the opposite of what the
// caller asked for and the opposite of what the endpoint's own documentation
// promised ("max 100"): a request for 200 returned 20, so asking for more got
// you less — and got it silently, with a 200 and a well-formed body.
//
// Every clamp in this repo goes through ClampPerPage instead, and
// clamp_sweep_test.go fails the build when the raw idiom reappears.
package pagination

// ClampPerPage resolves a requested page size against an endpoint's default and
// maximum.
//
//   - A size of zero or less — which includes an unparseable parameter, since
//     strconv.Atoi returns 0 on failure — means "no preference", and resolves
//     to defaultSize.
//   - A size above maxSize resolves to MAXSIZE, not to defaultSize. This is the
//     whole point of the function: an over-large request is a caller asking for
//     as much as it can get, and the honest answer to it is the most this
//     endpoint will serve.
//   - Anything in range is returned unchanged.
//
// A value so large it overflows an int is handled by the same maxSize branch:
// strconv.Atoi returns math.MaxInt alongside its range error, and MaxInt is
// above every maxSize in this repo.
//
// maxSize is assumed to be at least 1 and at least defaultSize; both hold at
// every call site, and clamp_sweep_test.go's inventory is where a new one is
// declared.
func ClampPerPage(requested, defaultSize, maxSize int) int {
	if requested < 1 {
		return defaultSize
	}
	if requested > maxSize {
		return maxSize
	}
	return requested
}

// ClampPage forces a 1-based page number to at least 1.
//
// There is no maximum: a page past the end of the data is a legitimate request
// that legitimately returns nothing, and capping it would silently serve some
// other page's rows under the number the caller asked for.
func ClampPage(requested int) int {
	if requested < 1 {
		return 1
	}
	return requested
}

// Offset converts a clamped 1-based page and page size into a row offset.
func Offset(page, perPage int) int {
	return (page - 1) * perPage
}

// HasMore reports whether rows remain beyond the page just built, for an
// endpoint that knows its exact total.
//
// This is the completeness signal a client needs and could not previously get:
// `total` alone forces every consumer to re-derive `offset+len < total` by
// hand, and a consumer that forgets — which is exactly what happened to the
// organization pickers in the sibling frontend — shows a truncated list with no
// sign it is truncated.
func HasMore(offset, returned, total int) bool {
	return offset+returned < total
}

// Probe is the page size to REQUEST from a store when the endpoint has no total
// to compare against: one row more than the caller asked for.
//
// Pair it with Trim. Fetching the extra row is what makes has_more exact rather
// than "the page came back full, so there are probably more" — a guess that is
// wrong for every list whose length is an exact multiple of the page size,
// which is precisely the case a picker's "load more" control gets stuck on.
func Probe(perPage int) int {
	return perPage + 1
}

// Trim cuts a Probe result back to the page the caller asked for and reports
// whether the probe row was there, i.e. whether more rows follow this page.
func Trim[T any](rows []T, perPage int) (page []T, hasMore bool) {
	if len(rows) > perPage {
		return rows[:perPage], true
	}
	return rows, false
}
