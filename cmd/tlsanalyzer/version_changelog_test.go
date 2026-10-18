package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestVersionIsTheNewestChangelogRelease keeps the version a source build
// prints in step with the newest release the changelog describes.
//
// The release workflow sets main.version with -ldflags, so the literal in this
// package reaches only binaries built from source, such as the README's
// build-from-source path. Retitling the changelog for a release without
// bumping the literal gives a source build of that release the previous
// version number. An [Unreleased] heading carries no version and is skipped:
// between releases the literal names the last release.
func TestVersionIsTheNewestChangelogRelease(t *testing.T) {
	path := filepath.Join("..", "..", "CHANGELOG.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	lines := strings.Split(string(body), "\n")

	heading := regexp.MustCompile(`^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$`)
	newest := ""
	for _, line := range lines {
		if m := heading.FindStringSubmatch(line); m != nil {
			newest = m[1]
			break
		}
	}
	if newest == "" {
		t.Fatalf("%s has no release heading of the form \"## [X.Y.Z] - YYYY-MM-DD\"", path)
	}
	if version != newest {
		t.Errorf("cmd/tlsanalyzer reports version %q but the newest release in %s is %q; "+
			"bump the version literals when retitling the changelog", version, path, newest)
	}

	link := "[" + newest + "]: https://github.com/csnp/tls-analyzer/releases/tag/v" + newest
	for _, line := range lines {
		if line == link {
			return
		}
	}
	t.Errorf("%s has no link reference for its newest release heading; want the line %q", path, link)
}
