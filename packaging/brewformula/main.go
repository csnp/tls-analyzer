// Command brewformula prints the Homebrew formula for a tls-analyzer release,
// with each sha256 taken from that release's checksums.txt.
//
// The release workflow publishes checksums.txt beside the archives. Reading it
// here means the digest on each sha256 line is the one published for the
// archive on the url line above it, instead of one copied by hand. From the
// repository root:
//
//	dir=$(mktemp -d)
//	curl -fsSL -o "$dir/checksums.txt" https://github.com/csnp/tls-analyzer/releases/download/v0.4.1/checksums.txt
//	go run ./packaging/brewformula -version 0.4.1 -checksums "$dir/checksums.txt" > "$dir/tlsanalyzer.rb"
//
// CONTRIBUTING.md says where the output goes.
//
// The formula installs the release binary for macOS and Linux, each on arm64
// and amd64, so it needs no Go toolchain and runs no build. Homebrew does not
// run on Windows, so the Windows zip is not in it.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"
)

// archiveSuffixes names the archives the formula installs by the release
// workflow's matrix suffix. The workflow publishes each one as
// tlsanalyzer-<suffix>.tar.gz with the tlsanalyzer binary at its top level.
var archiveSuffixes = []string{"darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64"}

// downloadURL is where a release's assets are published, up to the version.
const downloadURL = "https://github.com/csnp/tls-analyzer/releases/download/v"

var (
	releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256Digest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func archiveName(suffix string) string {
	return "tlsanalyzer-" + suffix + ".tar.gz"
}

// release is what the formula template reads.
type release struct {
	Version string
	digests map[string]string // archive name to its sha256 digest
}

// URL is the download address of the archive with the given suffix.
func (r release) URL(suffix string) string {
	return downloadURL + r.Version + "/" + archiveName(suffix)
}

// SHA256 is the digest checksums.txt gives the archive with the given suffix.
func (r release) SHA256(suffix string) (string, error) {
	digest, ok := r.digests[archiveName(suffix)]
	if !ok {
		return "", fmt.Errorf("checksums.txt has no digest for %s", archiveName(suffix))
	}
	return digest, nil
}

// formulaTemplate has no version line: Homebrew reads the version from the
// /download/v<version>/ part of each url.
var formulaTemplate = template.Must(template.New("tlsanalyzer.rb").Parse(`# Rendered by packaging/brewformula in github.com/csnp/tls-analyzer from the
# checksums.txt of release v{{.Version}}. For a new release, render it again
# instead of editing a url or sha256 line by hand.
class Tlsanalyzer < Formula
  desc "TLS security assessment with post-quantum readiness checks"
  homepage "https://github.com/csnp/tls-analyzer"
  license "MIT"

  on_macos do
    on_arm do
      url "{{.URL "darwin-arm64"}}"
      sha256 "{{.SHA256 "darwin-arm64"}}"
    end
    on_intel do
      url "{{.URL "darwin-amd64"}}"
      sha256 "{{.SHA256 "darwin-amd64"}}"
    end
  end

  on_linux do
    on_arm do
      url "{{.URL "linux-arm64"}}"
      sha256 "{{.SHA256 "linux-arm64"}}"
    end
    on_intel do
      url "{{.URL "linux-amd64"}}"
      sha256 "{{.SHA256 "linux-amd64"}}"
    end
  end

  def install
    bin.install "tlsanalyzer"
  end

  test do
    assert_match "qramm-tls-analyzer #{version}", shell_output("#{bin}/tlsanalyzer version")
  end
end
`))

func main() {
	version := flag.String("version", "", "release `version` the formula installs, such as 0.4.1")
	checksums := flag.String("checksums", "", "`path` to that release's checksums.txt")
	flag.Parse()
	if *version == "" || *checksums == "" || flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}

	sums, err := os.ReadFile(*checksums)
	if err == nil {
		var out []byte
		if out, err = formula(*version, sums); err == nil {
			_, err = os.Stdout.Write(out)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "brewformula:", err)
		os.Exit(1)
	}
}

// formula renders the formula for version from the contents of that release's
// checksums.txt. A leading "v" on version is dropped. It returns an error, and
// no formula, for a version that is not X.Y.Z, a line that is not a sha256
// digest and a file name, an archive given two different digests, and a
// checksums.txt without a digest for each archive the formula installs.
func formula(version string, checksums []byte) ([]byte, error) {
	version = strings.TrimPrefix(version, "v")
	if !releaseVersion.MatchString(version) {
		return nil, fmt.Errorf("version %q is not a release version such as 0.4.1", version)
	}
	digests, err := parseChecksums(checksums)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, suffix := range archiveSuffixes {
		if _, ok := digests[archiveName(suffix)]; !ok {
			missing = append(missing, archiveName(suffix))
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("checksums.txt has no digest for %s", strings.Join(missing, ", "))
	}

	var out bytes.Buffer
	if err := formulaTemplate.Execute(&out, release{Version: version, digests: digests}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// parseChecksums reads sha256sum output: a digest, white space and a file
// name, which sha256sum marks with a leading "*" in binary mode.
func parseChecksums(checksums []byte) (map[string]string, error) {
	digests := make(map[string]string)
	lines := bufio.NewScanner(bytes.NewReader(checksums))
	for n := 1; lines.Scan(); n++ {
		line := strings.TrimSpace(lines.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !sha256Digest.MatchString(fields[0]) {
			return nil, fmt.Errorf("checksums.txt line %d is not a sha256 digest and a file name: %q", n, line)
		}
		name := strings.TrimPrefix(fields[1], "*")
		if digest, ok := digests[name]; ok && digest != fields[0] {
			return nil, fmt.Errorf("checksums.txt gives %s two different digests", name)
		}
		digests[name] = fields[0]
	}
	if err := lines.Err(); err != nil {
		return nil, err
	}
	return digests, nil
}
