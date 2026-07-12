// querybuilder.go provides a small shared helper for assembling parameterized
// WHERE clauses with automatic $N placeholder numbering, replacing the
// hand-tracked argCount pattern that was duplicated verbatim across the
// module and provider search/list repositories (issue #565 finding [42]).
//
// Every user-supplied value is still passed as a bound parameter, never
// interpolated into SQL text — the builder only ever formats the integer
// placeholder index into the clause, matching the pre-existing behavior it
// factors out. See TestWhereBuilder for the parameterization guarantees this
// locks in.
package repositories

import (
	"fmt"
	"strings"
)

// whereBuilder accumulates parameterized WHERE conditions so repositories
// don't hand-track an argCount int and risk an off-by-one in the $%d
// numbering each time a new filterable field is added.
type whereBuilder struct {
	conditions []string
	args       []interface{}
}

// add appends a condition and its single bound argument. condFmt is a format
// string whose every %d verb is replaced with the SAME placeholder index —
// so a filter that references one value across multiple columns (e.g. an
// ILIKE over namespace/name/description) still binds a single argument. The
// value is always appended to the args slice, never formatted into the SQL.
func (b *whereBuilder) add(condFmt string, arg interface{}) {
	n := len(b.args) + 1
	placeholders := make([]interface{}, strings.Count(condFmt, "%d"))
	for i := range placeholders {
		placeholders[i] = n
	}
	b.conditions = append(b.conditions, fmt.Sprintf(condFmt, placeholders...))
	b.args = append(b.args, arg)
}

// clause returns the assembled "WHERE ..." string (empty when no conditions
// were added, so it can be spliced into a query with no filters) and the
// accumulated bound args.
func (b *whereBuilder) clause() (string, []interface{}) {
	if len(b.conditions) == 0 {
		return "", b.args
	}
	return "WHERE " + strings.Join(b.conditions, " AND "), b.args
}

// nextPlaceholder returns the $N index a caller should use for the next bound
// parameter it appends itself (e.g. LIMIT/OFFSET after the WHERE conditions).
func (b *whereBuilder) nextPlaceholder() int {
	return len(b.args) + 1
}
