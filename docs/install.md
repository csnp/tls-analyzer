# Installing QRAMM TLS Analyzer

The README's quick start builds the tool from source. This page covers the
other way in: a pre-built binary, and how to check it before you run it.

## Download Binary

Download pre-built binaries from [Releases](https://github.com/csnp/qramm-tls-analyzer/releases).

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
