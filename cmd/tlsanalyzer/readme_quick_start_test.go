package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestReadmeQuickStartLeadsWithTheReleaseBinary keeps the README's first way
// to install the tool one that needs no Go toolchain and no sudo.
//
// The quick start opened with git clone, go build and sudo mv, so a first scan
// needed Go 1.25+ and sudo, while each release from 0.4.0 publishes archives
// for macOS, Linux and Windows and a checksums.txt to check them against. The
// first bash block of the quick start has to download a release archive and
// checksums.txt by names the release workflow publishes, and no command in the
// quick start may run sudo.
func TestReadmeQuickStartLeadsWithTheReleaseBinary(t *testing.T) {
	path := filepath.Join("..", "..", "README.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	type command struct {
		line  int // line number in README.md
		block int // 0 for the quick start's first bash block
		text  string
	}
	var commands []command
	inQuickStart, inBash, block := false, false, -1
	for i, line := range strings.Split(string(body), "\n") {
		if line == "## Quick Start" {
			inQuickStart = true
			continue
		}
		if !inQuickStart {
			continue
		}
		if strings.HasPrefix(line, "## ") {
			break
		}
		fence := strings.TrimSpace(line)
		switch {
		case inBash && fence == "```":
			inBash = false
		case inBash:
			commands = append(commands, command{i + 1, block, strings.TrimSpace(line)})
		case fence == "```bash":
			inBash, block = true, block+1
		}
	}
	if len(commands) == 0 {
		t.Fatalf("%s has no bash block under \"## Quick Start\"", path)
	}

	published := releaseAssets(t)
	download := regexp.MustCompile(`releases/latest/download/(\S+)`)
	var downloads []string
	for _, c := range commands {
		if strings.HasPrefix(c.text, "sudo ") {
			t.Errorf("%s:%d: the quick start runs sudo: %s", path, c.line, c.text)
		}
		if c.block != 0 {
			continue
		}
		for _, tool := range []string{"git clone", "go build", "go install"} {
			if strings.Contains(c.text, tool) {
				t.Errorf("%s:%d: the quick start's first bash block runs %s, a step of building from source; "+
					"lead with the release binary, which needs no Go toolchain: %s", path, c.line, tool, c.text)
			}
		}
		for _, m := range download.FindAllStringSubmatch(c.text, -1) {
			downloads = append(downloads, m[1])
			if !published[m[1]] {
				t.Errorf("%s:%d: downloads %s, which the release workflow does not publish", path, c.line, m[1])
			}
		}
	}
	archive := false
	checksums := false
	for _, name := range downloads {
		archive = archive || strings.HasPrefix(name, "tlsanalyzer-")
		checksums = checksums || name == "checksums.txt"
	}
	if !archive || !checksums {
		t.Errorf("%s: the quick start's first bash block downloads %q from the latest release; "+
			"want a release archive and checksums.txt", path, downloads)
	}
}

// releaseAssets returns the names .github/workflows/release.yml publishes: an
// archive per matrix suffix, a zip for Windows and a tar.gz for the others, as
// its "Create archive" step builds them, and checksums.txt.
func releaseAssets(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	assets := map[string]bool{"checksums.txt": true}
	for _, m := range regexp.MustCompile(`(?m)^\s*suffix:\s*(\S+)\s*$`).FindAllStringSubmatch(string(body), -1) {
		if strings.HasPrefix(m[1], "windows-") {
			assets["tlsanalyzer-"+m[1]+".zip"] = true
		} else {
			assets["tlsanalyzer-"+m[1]+".tar.gz"] = true
		}
	}
	if len(assets) == 1 {
		t.Fatalf("%s has no matrix suffix lines to name its archives by", path)
	}
	return assets
}
