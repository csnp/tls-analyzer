package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadmeBadgesComeFromServicesThatAnswer keeps the README header free of
// badges whose service has shut down.
//
// goreportcard.com retired its service: fetched on 2026-10-17, its badge for
// this module rendered the text "go report: retired" instead of a grade, so the
// README header showed a broken badge to every visitor.
func TestReadmeBadgesComeFromServicesThatAnswer(t *testing.T) {
	path := filepath.Join("..", "..", "README.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	retired := []string{"goreportcard.com"}
	for i, line := range strings.Split(string(body), "\n") {
		for _, host := range retired {
			if strings.Contains(line, host) {
				t.Errorf("README.md:%d links to %s, which has retired its service: %s",
					i+1, host, strings.TrimSpace(line))
			}
		}
	}
}
