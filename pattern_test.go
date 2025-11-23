package permfs

import (
	"testing"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		// Exact matches
		{
			name:     "exact match",
			pattern:  "/home/user/file.txt",
			path:     "/home/user/file.txt",
			expected: true,
		},
		{
			name:     "exact mismatch",
			pattern:  "/home/user/file.txt",
			path:     "/home/user/other.txt",
			expected: false,
		},

		// Single star patterns
		{
			name:     "single star matches files in directory",
			pattern:  "/public/*.txt",
			path:     "/public/file.txt",
			expected: true,
		},
		{
			name:     "single star doesn't match subdirectories",
			pattern:  "/public/*.txt",
			path:     "/public/sub/file.txt",
			expected: false,
		},
		{
			name:     "single star matches any extension",
			pattern:  "/data/file.*",
			path:     "/data/file.json",
			expected: true,
		},

		// Question mark patterns
		{
			name:     "question mark matches single character",
			pattern:  "/data/file?.txt",
			path:     "/data/file1.txt",
			expected: true,
		},
		{
			name:     "question mark doesn't match multiple characters",
			pattern:  "/data/file?.txt",
			path:     "/data/file12.txt",
			expected: false,
		},

		// Double star patterns
		{
			name:     "double star matches all files under directory",
			pattern:  "/data/user123/**",
			path:     "/data/user123/file.txt",
			expected: true,
		},
		{
			name:     "double star matches nested files",
			pattern:  "/data/user123/**",
			path:     "/data/user123/docs/secret/file.txt",
			expected: true,
		},
		{
			name:     "double star doesn't match parent directory",
			pattern:  "/data/user123/**",
			path:     "/data/user456/file.txt",
			expected: false,
		},
		{
			name:     "double star in middle matches subdirectories",
			pattern:  "/temp/**/*.log",
			path:     "/temp/logs/app.log",
			expected: true,
		},
		{
			name:     "double star in middle matches deeply nested",
			pattern:  "/temp/**/*.log",
			path:     "/temp/2024/01/15/app.log",
			expected: true,
		},
		{
			name:     "double star matches any user documents",
			pattern:  "/home/*/documents/**",
			path:     "/home/alice/documents/work/report.pdf",
			expected: true,
		},
		{
			name:     "double star at root matches everything",
			pattern:  "/**",
			path:     "/any/path/to/file.txt",
			expected: true,
		},
		{
			name:     "double star can match zero directories",
			pattern:  "/data/**/file.txt",
			path:     "/data/file.txt",
			expected: true,
		},

		// Complex patterns
		{
			name:     "combination of wildcards",
			pattern:  "/home/*/docs/**/*.txt",
			path:     "/home/alice/docs/work/notes.txt",
			expected: true,
		},
		{
			name:     "multiple single stars",
			pattern:  "/data/*/*/file.txt",
			path:     "/data/2024/01/file.txt",
			expected: true,
		},

		// Edge cases
		{
			name:     "root path",
			pattern:  "/",
			path:     "/",
			expected: true,
		},
		{
			name:     "empty pattern and path",
			pattern:  "",
			path:     "",
			expected: true,
		},
		{
			name:     "pattern with trailing slash",
			pattern:  "/data/",
			path:     "/data",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchPattern(tt.pattern, tt.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("matchPattern(%q, %q) = %v, want %v",
					tt.pattern, tt.path, got, tt.expected)
			}
		})
	}
}

func TestPatternMatcher(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{
			name:     "exact match with matcher",
			pattern:  "/exact/path",
			path:     "/exact/path",
			expected: true,
		},
		{
			name:     "wildcard match with matcher",
			pattern:  "/data/**/*.json",
			path:     "/data/configs/app.json",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewPatternMatcher(tt.pattern)
			if err != nil {
				t.Fatalf("failed to create matcher: %v", err)
			}

			got, err := matcher.Match(tt.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("matcher.Match(%q) = %v, want %v",
					tt.path, got, tt.expected)
			}
		})
	}
}

func BenchmarkPatternMatch(b *testing.B) {
	benchmarks := []struct {
		name    string
		pattern string
		path    string
	}{
		{
			name:    "exact match",
			pattern: "/home/user/file.txt",
			path:    "/home/user/file.txt",
		},
		{
			name:    "single star",
			pattern: "/data/*.txt",
			path:    "/data/file.txt",
		},
		{
			name:    "double star simple",
			pattern: "/data/**",
			path:    "/data/sub/file.txt",
		},
		{
			name:    "double star complex",
			pattern: "/temp/**/*.log",
			path:    "/temp/2024/01/15/app.log",
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = matchPattern(bm.pattern, bm.path)
			}
		})
	}
}

func BenchmarkPatternMatcherCompiled(b *testing.B) {
	pattern := "/temp/**/*.log"
	path := "/temp/2024/01/15/app.log"

	matcher, _ := NewPatternMatcher(pattern)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = matcher.Match(path)
	}
}
