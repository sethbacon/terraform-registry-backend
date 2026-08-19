package rolepolicy

import "strings"

// A deliberately small SQL scanner: enough to find statement boundaries,
// top-level keywords, balanced parentheses and string literals without
// mistaking a `;` inside a dollar-quoted plpgsql body -- or an apostrophe inside
// a `--` comment -- for either.
//
// It is not a parser and does not try to be. Everything it cannot account for
// reaches applyStatement, which fails closed.

// splitStatements returns dir-order statements with comments removed.
func splitStatements(sql string) []string {
	var out []string
	var b strings.Builder
	rs := []rune(sql)
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" {
			out = append(out, s)
		}
		b.Reset()
	}
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case c == '-' && i+1 < len(rs) && rs[i+1] == '-':
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			b.WriteRune(' ')
		case c == '/' && i+1 < len(rs) && rs[i+1] == '*':
			depth := 1
			i += 2
			for i < len(rs) && depth > 0 {
				switch {
				case rs[i] == '/' && i+1 < len(rs) && rs[i+1] == '*':
					depth++
					i += 2
				case rs[i] == '*' && i+1 < len(rs) && rs[i+1] == '/':
					depth--
					i += 2
				default:
					i++
				}
			}
			b.WriteRune(' ')
		case c == '\'':
			b.WriteRune(c)
			i++
			for i < len(rs) {
				if rs[i] == '\'' {
					if i+1 < len(rs) && rs[i+1] == '\'' {
						b.WriteString("''")
						i += 2
						continue
					}
					b.WriteRune('\'')
					i++
					break
				}
				b.WriteRune(rs[i])
				i++
			}
		case c == '$':
			tag, ok := dollarTag(rs, i)
			if !ok {
				b.WriteRune(c)
				i++
				continue
			}
			b.WriteString(tag)
			i += len([]rune(tag))
			closeAt := indexRunes(rs, []rune(tag), i)
			if closeAt < 0 {
				b.WriteString(string(rs[i:]))
				i = len(rs)
				continue
			}
			b.WriteString(string(rs[i:closeAt]))
			b.WriteString(tag)
			i = closeAt + len([]rune(tag))
		case c == ';':
			flush()
			i++
		default:
			b.WriteRune(c)
			i++
		}
	}
	flush()
	return out
}

// dollarTag recognises `$$` and `$tag$`. `$1` is a bind placeholder, not a tag,
// so a tag may not start with a digit.
func dollarTag(rs []rune, i int) (string, bool) {
	if rs[i] != '$' {
		return "", false
	}
	j := i + 1
	// `$1` is a bind placeholder, not a dollar-quote tag.
	if j < len(rs) && rs[j] >= '0' && rs[j] <= '9' {
		return "", false
	}
	for j < len(rs) && isIdentRune(rs[j]) {
		j++
	}
	if j < len(rs) && rs[j] == '$' {
		return string(rs[i : j+1]), true
	}
	return "", false
}

func isIdentRune(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func indexRunes(hay, needle []rune, from int) int {
	if len(needle) == 0 {
		return -1
	}
	for i := from; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// scan walks s calling visit at every index that is outside a string literal,
// with the parenthesis depth at that point. visit returning false stops the walk.
func scan(s string, visit func(i, depth int) bool) {
	rs := []rune(s)
	depth := 0
	for i := 0; i < len(rs); {
		switch rs[i] {
		case '\'':
			i++
			for i < len(rs) {
				if rs[i] == '\'' {
					if i+1 < len(rs) && rs[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			continue
		case '$':
			if tag, ok := dollarTag(rs, i); ok {
				closeAt := indexRunes(rs, []rune(tag), i+len([]rune(tag)))
				if closeAt < 0 {
					return
				}
				i = closeAt + len([]rune(tag))
				continue
			}
		// Brackets nest exactly like parentheses here: a comma inside an
		// `ARRAY['a', 'b']` constructor is not a top-level separator, and
		// counting only parentheses split such an operand in half.
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		}
		if !visit(runeToByteIndex(s, i), depth) {
			return
		}
		i++
	}
}

// runeToByteIndex is O(n) per call in general; the fragments here are short
// statements, and correctness on multi-byte characters matters more than the
// constant factor.
func runeToByteIndex(s string, runeIdx int) int {
	n := 0
	for i := range s {
		if n == runeIdx {
			return i
		}
		n++
	}
	return len(s)
}

// indexTopLevelKeyword returns the byte index of kw (a lower-case word, possibly
// several words separated by single spaces) at parenthesis depth zero, outside
// any string literal, on a word boundary. -1 when absent.
func indexTopLevelKeyword(s, kw string) int {
	lower := strings.ToLower(s)
	found := -1
	scan(s, func(i, depth int) bool {
		if depth != 0 {
			return true
		}
		if !matchKeywordAt(lower, i, kw) {
			return true
		}
		found = i
		return false
	})
	return found
}

// matchKeywordAt compares against a keyword whose internal spacing may be any
// run of whitespace in the source.
func matchKeywordAt(lower string, i int, kw string) bool {
	if i > 0 && isIdentByte(lower[i-1]) {
		return false
	}
	j := i
	for k := 0; k < len(kw); k++ {
		if kw[k] == ' ' {
			consumed := false
			for j < len(lower) && isSpaceByte(lower[j]) {
				j++
				consumed = true
			}
			if !consumed {
				return false
			}
			continue
		}
		if j >= len(lower) || lower[j] != kw[k] {
			return false
		}
		j++
	}
	return j >= len(lower) || !isIdentByte(lower[j])
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// hasLeadingKeyword reports whether s begins with kw on a word boundary.
func hasLeadingKeyword(s, kw string) bool {
	return matchKeywordAt(strings.ToLower(s), 0, kw)
}

// indexTopLevelRune finds r at depth zero outside string literals.
func indexTopLevelRune(s string, r rune) int {
	found := -1
	scan(s, func(i, depth int) bool {
		if depth != 0 || rune(s[i]) != r {
			return true
		}
		// `<=`, `>=`, `!=`, `<>` and `:=` are not assignment separators.
		if r == '=' {
			if i > 0 && strings.ContainsRune("<>!:", rune(s[i-1])) {
				return true
			}
			if i+1 < len(s) && s[i+1] == '=' {
				return true
			}
		}
		found = i
		return false
	})
	return found
}

// splitTopLevel splits on sep at depth zero outside string literals.
func splitTopLevel(s string, sep rune) []string {
	var cuts []int
	scan(s, func(i, depth int) bool {
		if depth == 0 && rune(s[i]) == sep {
			cuts = append(cuts, i)
		}
		return true
	})
	out := make([]string, 0, len(cuts)+1)
	prev := 0
	for _, c := range cuts {
		out = append(out, s[prev:c])
		prev = c + 1
	}
	out = append(out, s[prev:])
	return out
}

// splitTopLevelKeyword splits on a keyword at depth zero outside string literals.
func splitTopLevelKeyword(s, kw string) []string {
	lower := strings.ToLower(s)
	type cut struct{ start, end int }
	var cuts []cut
	scan(s, func(i, depth int) bool {
		if depth != 0 || !matchKeywordAt(lower, i, kw) {
			return true
		}
		if len(cuts) > 0 && i < cuts[len(cuts)-1].end {
			return true
		}
		cuts = append(cuts, cut{i, i + len(kw)})
		return true
	})
	out := make([]string, 0, len(cuts)+1)
	prev := 0
	for _, c := range cuts {
		out = append(out, s[prev:c.start])
		prev = c.end
	}
	out = append(out, s[prev:])
	return out
}

// parenGroup reads a balanced `( ... )` from the front of s (after leading
// whitespace) and returns its contents and whatever follows.
func parenGroup(s string) (inner, rest string, ok bool) {
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if !strings.HasPrefix(trimmed, "(") {
		return "", s, false
	}
	closeAt := -1
	scan(trimmed, func(i, depth int) bool {
		if trimmed[i] == ')' && depth == 0 {
			closeAt = i
			return false
		}
		return true
	})
	if closeAt < 0 {
		return "", s, false
	}
	return trimmed[1:closeAt], trimmed[closeAt+1:], true
}
