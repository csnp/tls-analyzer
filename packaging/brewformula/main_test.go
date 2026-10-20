package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// stubDigest stands in for a sha256 digest: 64 copies of one hex digit, so
// each archive in a test checksums.txt has a digest that is easy to tell apart.
func stubDigest(digit string) string {
	return strings.Repeat(digit, 64)
}

// publishedChecksums is a checksums.txt in the shape the release workflow
// writes: sha256sum output for the five archives, sorted by name.
func publishedChecksums() string {
	return stubDigest("1") + "  tlsanalyzer-darwin-amd64.tar.gz\n" +
		stubDigest("2") + "  tlsanalyzer-darwin-arm64.tar.gz\n" +
		stubDigest("3") + "  tlsanalyzer-linux-amd64.tar.gz\n" +
		stubDigest("4") + "  tlsanalyzer-linux-arm64.tar.gz\n" +
		stubDigest("5") + "  tlsanalyzer-windows-amd64.zip\n"
}

// TestFormulaPairsEachURLWithItsArchiveDigest checks every url line of the
// formula: it sits in the on_<os> and on_<arch> blocks of the platform its
// archive was built for, it names that archive under the release's version,
// and the line after it carries the digest checksums.txt gives that archive.
// Homebrew installs whatever the url names on the platform whose block holds
// it, and refuses a download whose digest is not the formula's.
func TestFormulaPairsEachURLWithItsArchiveDigest(t *testing.T) {
	out, err := formula("0.4.1", []byte(publishedChecksums()))
	if err != nil {
		t.Fatalf("formula: %v", err)
	}

	wantDigest := map[string]string{
		"darwin-amd64": stubDigest("1"),
		"darwin-arm64": stubDigest("2"),
		"linux-amd64":  stubDigest("3"),
		"linux-arm64":  stubDigest("4"),
	}
	blockOS := map[string]string{"on_macos do": "darwin", "on_linux do": "linux"}
	blockArch := map[string]string{"on_arm do": "arm64", "on_intel do": "amd64"}
	urlLine := regexp.MustCompile(`^url "(.*)"$`)

	lines := strings.Split(string(out), "\n")
	var goos, goarch string
	urls := map[string]int{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if v, ok := blockOS[line]; ok {
			goos, goarch = v, ""
			continue
		}
		if v, ok := blockArch[line]; ok {
			goarch = v
			continue
		}
		m := urlLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		platform := goos + "-" + goarch
		urls[platform]++
		want := "https://github.com/csnp/tls-analyzer/releases/download/v0.4.1/tlsanalyzer-" + platform + ".tar.gz"
		if m[1] != want {
			t.Errorf("formula line %d, in the block for %s: url %q, want %q", i+1, platform, m[1], want)
		}
		next := ""
		if i+1 < len(lines) {
			next = strings.TrimSpace(lines[i+1])
		}
		if wantLine := `sha256 "` + wantDigest[platform] + `"`; next != wantLine {
			t.Errorf("formula line %d, after the url for %s: %q, want %q", i+2, platform, next, wantLine)
		}
	}
	for platform := range wantDigest {
		if urls[platform] != 1 {
			t.Errorf("formula has %d url lines for %s, want 1", urls[platform], platform)
		}
	}
	if len(urls) != len(wantDigest) {
		t.Errorf("formula has url lines for %v, want one for each of %v", urls, archiveSuffixes)
	}
	if strings.Contains(string(out), stubDigest("5")) {
		t.Errorf("formula carries the digest of the Windows zip, which Homebrew cannot install:\n%s", out)
	}
}

// TestFormulaAcceptsTheTagAndBinaryModeNames covers two inputs a maintainer is
// likely to pass: the release tag, v0.4.1, as the version, and a checksums.txt
// written by sha256sum in binary mode, which puts "*" before each file name.
func TestFormulaAcceptsTheTagAndBinaryModeNames(t *testing.T) {
	binaryMode := strings.ReplaceAll(publishedChecksums(), "  tlsanalyzer-", " *tlsanalyzer-")
	out, err := formula("v0.4.1", []byte(binaryMode))
	if err != nil {
		t.Fatalf("formula: %v", err)
	}
	for _, want := range []string{
		"checksums.txt of release v0.4.1.",
		`url "https://github.com/csnp/tls-analyzer/releases/download/v0.4.1/tlsanalyzer-darwin-arm64.tar.gz"`,
		`sha256 "` + stubDigest("2") + `"`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("formula does not contain %q:\n%s", want, out)
		}
	}
}

// TestFormulaRefusesInputItCannotPairWithAnArchive checks that each kind of
// bad input gives an error and no formula, rather than a formula with an empty
// or misplaced sha256 line.
func TestFormulaRefusesInputItCannotPairWithAnArchive(t *testing.T) {
	published := publishedChecksums()
	tests := []struct {
		name      string
		version   string
		checksums string
		wantErr   string
	}{
		{
			name:      "an archive missing",
			version:   "0.4.1",
			checksums: strings.Replace(published, stubDigest("4")+"  tlsanalyzer-linux-arm64.tar.gz\n", "", 1),
			wantErr:   "checksums.txt has no digest for tlsanalyzer-linux-arm64.tar.gz",
		},
		{
			name:      "an empty file",
			version:   "0.4.1",
			checksums: "",
			wantErr: "checksums.txt has no digest for tlsanalyzer-darwin-arm64.tar.gz, " +
				"tlsanalyzer-darwin-amd64.tar.gz, tlsanalyzer-linux-arm64.tar.gz, tlsanalyzer-linux-amd64.tar.gz",
		},
		{
			name:      "a digest one digit short",
			version:   "0.4.1",
			checksums: stubDigest("6")[1:] + "  tlsanalyzer-darwin-amd64.tar.gz\n" + published,
			wantErr:   "checksums.txt line 1 is not a sha256 digest and a file name",
		},
		{
			name:      "an upper-case digest",
			version:   "0.4.1",
			checksums: published + strings.ToUpper(stubDigest("a")) + "  tlsanalyzer-darwin-amd64.tar.gz\n",
			wantErr:   "checksums.txt line 6 is not a sha256 digest and a file name",
		},
		{
			name:      "a digest without a file name",
			version:   "0.4.1",
			checksums: stubDigest("6") + "\n" + published,
			wantErr:   "checksums.txt line 1 is not a sha256 digest and a file name",
		},
		{
			name:      "an archive given two digests",
			version:   "0.4.1",
			checksums: published + stubDigest("6") + "  tlsanalyzer-darwin-arm64.tar.gz\n",
			wantErr:   "checksums.txt gives tlsanalyzer-darwin-arm64.tar.gz two different digests",
		},
		{
			name:      "a version without a patch number",
			version:   "0.4",
			checksums: published,
			wantErr:   `version "0.4" is not a release version such as 0.4.1`,
		},
		{
			name:      "a pre-release version",
			version:   "0.5.0-rc.1",
			checksums: published,
			wantErr:   `version "0.5.0-rc.1" is not a release version such as 0.4.1`,
		},
		{
			name:      "a word for a version",
			version:   "latest",
			checksums: published,
			wantErr:   `version "latest" is not a release version such as 0.4.1`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := formula(tt.version, []byte(tt.checksums))
			if err == nil {
				t.Fatalf("formula returned no error, and this formula:\n%s", out)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q, want it to contain %q", err, tt.wantErr)
			}
			if out != nil {
				t.Errorf("formula returned %d bytes along with its error", len(out))
			}
		})
	}
}

// TestArchivesAreTheOnesTheReleaseWorkflowPublishes ties the formula to the
// workflow that builds the archives it downloads. The formula names each
// archive by a matrix suffix of that workflow and installs the file
// tlsanalyzer from the top level of the archive, so renaming a suffix, the
// archive or the binary there breaks the formula, and this test says so before
// a release does.
func TestArchivesAreTheOnesTheReleaseWorkflowPublishes(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	workflow := string(body)

	suffixes := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*suffix:\s*(\S+)\s*$`).FindAllStringSubmatch(workflow, -1) {
		suffixes[m[1]] = true
	}
	for _, suffix := range archiveSuffixes {
		if !suffixes[suffix] {
			t.Errorf("%s builds no archive with the suffix %s, which the formula downloads", path, suffix)
		}
	}

	archive := "tar -czvf tlsanalyzer-${{ matrix.suffix }}.tar.gz tlsanalyzer${{ matrix.ext }}"
	if !strings.Contains(workflow, archive) {
		t.Errorf("%s does not run %q; the formula downloads tlsanalyzer-<suffix>.tar.gz and installs "+
			"the tlsanalyzer at its top level, so update packaging/brewformula to match the archives", path, archive)
	}
}
