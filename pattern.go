package permfs

import (
	"path"
	"path/filepath"
	"strings"
)

// matchPattern checks if a path matches a pattern with wildcard support
// Supports:
//   - * matches any sequence of non-separator characters
//   - ** matches any sequence including separators (recursive)
//   - ? matches any single non-separator character
func matchPattern(pattern, pathStr string) (bool, error) {
	// Normalize paths to use forward slashes for pattern matching
	// This ensures consistent behavior across Windows, macOS, and Linux
	pattern = filepath.ToSlash(filepath.Clean(pattern))
	pathStr = filepath.ToSlash(filepath.Clean(pathStr))

	// Use path.Clean (not filepath.Clean) to normalize with forward slashes
	pattern = path.Clean(pattern)
	pathStr = path.Clean(pathStr)

	// Handle exact match
	if pattern == pathStr {
		return true, nil
	}

	// Handle ** pattern - matches everything under a directory
	if strings.Contains(pattern, "**") {
		return matchDoubleStarPattern(pattern, pathStr)
	}

	// Use path.Match for single * and ? patterns (works with forward slashes)
	matched, err := path.Match(pattern, pathStr)
	if err != nil {
		return false, ErrInvalidPattern
	}

	return matched, nil
}

// matchDoubleStarPattern handles patterns containing **
func matchDoubleStarPattern(pattern, path string) (bool, error) {
	// Split pattern into segments
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	return matchSegments(patternParts, pathParts, 0, 0)
}

// matchSegments recursively matches pattern segments against path segments
func matchSegments(patternParts, pathParts []string, pi, pathi int) (bool, error) {
	// If we've consumed all pattern parts
	if pi >= len(patternParts) {
		// Match if we've also consumed all path parts
		return pathi >= len(pathParts), nil
	}

	// If we've consumed all path parts but still have pattern parts
	if pathi >= len(pathParts) {
		// Only match if all remaining pattern parts are **
		for i := pi; i < len(patternParts); i++ {
			if patternParts[i] != "**" {
				return false, nil
			}
		}
		return true, nil
	}

	currentPattern := patternParts[pi]

	// Handle ** pattern
	if currentPattern == "**" {
		// ** can match zero or more path segments

		// Try matching zero segments (skip the **)
		matched, err := matchSegments(patternParts, pathParts, pi+1, pathi)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}

		// Try matching one or more segments
		for i := pathi; i < len(pathParts); i++ {
			matched, err := matchSegments(patternParts, pathParts, pi+1, i+1)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}

		return false, nil
	}

	// Handle regular patterns (with * and ?)
	matched, err := path.Match(currentPattern, pathParts[pathi])
	if err != nil {
		return false, ErrInvalidPattern
	}

	if !matched {
		return false, nil
	}

	// Continue with next segments
	return matchSegments(patternParts, pathParts, pi+1, pathi+1)
}

// PatternMatcher provides compiled pattern matching
type PatternMatcher struct {
	pattern string
	hasGlob bool
}

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher(pattern string) (*PatternMatcher, error) {
	// Normalize to forward slashes for consistent pattern matching
	pattern = path.Clean(filepath.ToSlash(filepath.Clean(pattern)))
	hasGlob := strings.ContainsAny(pattern, "*?")

	return &PatternMatcher{
		pattern: pattern,
		hasGlob: hasGlob,
	}, nil
}

// Match checks if a path matches the pattern
func (pm *PatternMatcher) Match(pathStr string) (bool, error) {
	// Normalize to forward slashes for consistent pattern matching
	normalizedPath := path.Clean(filepath.ToSlash(filepath.Clean(pathStr)))

	// Fast path for exact matches
	if !pm.hasGlob {
		return pm.pattern == normalizedPath, nil
	}

	return matchPattern(pm.pattern, pathStr)
}

// Pattern returns the original pattern string
func (pm *PatternMatcher) Pattern() string {
	return pm.pattern
}
