// filter.go provides version-filtering helpers shared between the mirror sync job
// and the pull-through provider caching service.
package mirror

import (
	"log"
	"sort"
	"strconv"
	"strings"
)

// FilterVersions filters a list of provider versions based on the version filter string.
// Supported filter formats:
//   - "3." or "3.x" — all versions starting with "3."
//   - "latest:5"    — the latest 5 versions (sorted by semver descending)
//   - "3.74.0,3.73.0" — specific comma-separated versions
//   - ">=3.0.0"     — versions satisfying a semver constraint
//   - "" or nil     — all versions (no filtering)
func FilterVersions(versions []ProviderVersion, filter *string) []ProviderVersion {
	if filter == nil || *filter == "" {
		return versions
	}

	filterStr := strings.TrimSpace(*filter)

	if strings.HasPrefix(filterStr, "latest:") {
		countStr := strings.TrimPrefix(filterStr, "latest:")
		count, err := strconv.Atoi(countStr)
		if err != nil || count <= 0 {
			log.Printf("Invalid latest:N filter format: %s, using all versions", filterStr)
			return versions
		}
		return filterLatestVersions(versions, count)
	}

	if strings.HasSuffix(filterStr, ".") || strings.HasSuffix(filterStr, ".x") {
		prefix := strings.TrimSuffix(filterStr, "x")
		return filterVersionsByPrefix(versions, prefix)
	}

	if strings.HasPrefix(filterStr, ">=") || strings.HasPrefix(filterStr, ">") ||
		strings.HasPrefix(filterStr, "<=") || strings.HasPrefix(filterStr, "<") {
		return filterVersionsBySemverConstraint(versions, filterStr)
	}

	if strings.Contains(filterStr, ",") {
		return filterVersionsByList(versions, filterStr)
	}

	filtered := filterVersionsByPrefix(versions, filterStr+".")
	if len(filtered) > 0 {
		return filtered
	}
	return filterVersionsByList(versions, filterStr)
}

func filterLatestVersions(versions []ProviderVersion, count int) []ProviderVersion {
	if len(versions) <= count {
		return versions
	}
	sorted := make([]ProviderVersion, len(versions))
	copy(sorted, versions)
	sort.Slice(sorted, func(i, j int) bool {
		return CompareSemver(sorted[i].Version, sorted[j].Version) > 0
	})
	return sorted[:count]
}

func filterVersionsByPrefix(versions []ProviderVersion, prefix string) []ProviderVersion {
	var filtered []ProviderVersion
	for _, v := range versions {
		if strings.HasPrefix(v.Version, prefix) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func filterVersionsByList(versions []ProviderVersion, list string) []ProviderVersion {
	wanted := make(map[string]bool)
	for _, v := range strings.Split(list, ",") {
		wanted[strings.TrimSpace(v)] = true
	}
	var filtered []ProviderVersion
	for _, v := range versions {
		if wanted[v.Version] {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func filterVersionsBySemverConstraint(versions []ProviderVersion, constraint string) []ProviderVersion {
	var op, targetVersion string
	switch {
	case strings.HasPrefix(constraint, ">="):
		op, targetVersion = ">=", strings.TrimPrefix(constraint, ">=")
	case strings.HasPrefix(constraint, "<="):
		op, targetVersion = "<=", strings.TrimPrefix(constraint, "<=")
	case strings.HasPrefix(constraint, ">"):
		op, targetVersion = ">", strings.TrimPrefix(constraint, ">")
	case strings.HasPrefix(constraint, "<"):
		op, targetVersion = "<", strings.TrimPrefix(constraint, "<")
	default:
		return versions
	}
	targetVersion = strings.TrimSpace(targetVersion)

	var filtered []ProviderVersion
	for _, v := range versions {
		cmp := CompareSemver(v.Version, targetVersion)
		switch op {
		case ">=":
			if cmp >= 0 {
				filtered = append(filtered, v)
			}
		case ">":
			if cmp > 0 {
				filtered = append(filtered, v)
			}
		case "<=":
			if cmp <= 0 {
				filtered = append(filtered, v)
			}
		case "<":
			if cmp < 0 {
				filtered = append(filtered, v)
			}
		}
	}
	return filtered
}

// CompareSemver compares two semver strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareSemver(a, b string) int {
	aParts := parseSemverParts(a)
	bParts := parseSemverParts(b)
	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}
	return 0
}

func parseSemverParts(version string) [3]int {
	version = strings.TrimPrefix(version, "v")
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}
	parts := strings.Split(version, ".")
	var result [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		val, _ := strconv.Atoi(parts[i])
		result[i] = val
	}
	return result
}
