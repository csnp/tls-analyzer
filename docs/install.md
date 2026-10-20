# Installing QRAMM TLS Analyzer

The README's quick start downloads the pre-built binary for macOS on Apple
silicon and checks it before unpacking it. This page names the archive for each
platform and explains the check.

## Download Binary

Every release from 0.4.0 publishes one archive per platform:

| Platform | Archive |
|---|---|
| macOS on Apple silicon | `tlsanalyzer-darwin-arm64.tar.gz` |
| macOS on Intel | `tlsanalyzer-darwin-amd64.tar.gz` |
| Linux on x86-64 | `tlsanalyzer-linux-amd64.tar.gz` |
| Linux on ARM64 | `tlsanalyzer-linux-arm64.tar.gz` |
| Windows on x86-64 | `tlsanalyzer-windows-amd64.zip` |

The latest release's files download from
`https://github.com/csnp/tls-analyzer/releases/latest/download/` followed by the
file name, which is how the README's block fetches them. Every release is also
listed on [Releases](https://github.com/csnp/qramm-tls-analyzer/releases).

Every release from 0.4.0 also publishes `checksums.txt`. Download it into the same
directory as the archive and verify before extracting:

```bash
# macOS
shasum -a 256 -c --ignore-missing checksums.txt
# Linux
sha256sum -c --ignore-missing checksums.txt
```

`--ignore-missing` is needed because the file lists all five archives and you will
normally have downloaded one. Without it, the four you did not download are
reported as failures and the command exits non-zero. Expected output is
`<archive>: OK`.
