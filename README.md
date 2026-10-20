<h1 align="center">QRAMM TLS Analyzer</h1>

<p align="center">
  <strong>Quantum-Ready TLS Security Assessment Tool</strong>
</p>

<p align="center">
  <a href="https://github.com/csnp/qramm-tls-analyzer/actions"><img src="https://github.com/csnp/qramm-tls-analyzer/workflows/CI/badge.svg" alt="CI Status"></a>
  <a href="https://pkg.go.dev/github.com/csnp/qramm-tls-analyzer"><img src="https://pkg.go.dev/badge/github.com/csnp/qramm-tls-analyzer.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#what-it-does">What it does</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#output-formats">Output Formats</a> &bull;
  <a href="#policies">Policies</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

**QRAMM TLS Analyzer** is an open-source command-line tool that performs comprehensive TLS security analysis with a focus on **post-quantum cryptography (PQC) readiness**. As quantum computing advances, organizations must prepare their cryptographic infrastructure for the post-quantum era. This tool helps you understand your current TLS posture and provides actionable guidance for CNSA 2.0 compliance.

Part of the [QRAMM (Quantum Readiness Assurance Maturity Model)](https://qramm.org) toolkit, developed by the [Cyber Security Non-Profit (CSNP)](https://csnp.org).

> **Responsible use warning**
>
> This tool performs active network connections to analyze TLS configurations. **Only scan systems and domains you own or have explicit written authorization to test.** Unauthorized scanning may violate laws and regulations in your jurisdiction. The authors assume no liability for misuse of this tool.

## Quick Start

### Option 1: Download a binary

This needs no Go toolchain and no `sudo`. On macOS with Apple silicon, copy and
paste this block. It downloads the latest release's archive and its
`checksums.txt`, checks the archive against that file, and unpacks the
`tlsanalyzer` binary into the current directory:

```bash
curl -fsSLO https://github.com/csnp/tls-analyzer/releases/latest/download/tlsanalyzer-darwin-arm64.tar.gz
curl -fsSLO https://github.com/csnp/tls-analyzer/releases/latest/download/checksums.txt
shasum -a 256 -c --ignore-missing checksums.txt && tar -xzf tlsanalyzer-darwin-arm64.tar.gz
./tlsanalyzer version
```

`tar` runs only when the check prints `tlsanalyzer-darwin-arm64.tar.gz: OK`. For
an Intel Mac, Linux or Windows, [docs/install.md](docs/install.md) names the
archive to download.

### Option 2: Build from source

Requires Go 1.25+ ([install Go](https://go.dev/doc/install)), which is what `go.mod` declares.

Copy and paste this entire block:

```bash
git clone https://github.com/csnp/qramm-tls-analyzer.git
cd qramm-tls-analyzer
go build -o tlsanalyzer ./cmd/tlsanalyzer
./tlsanalyzer version
```

### Run your first scan

From the directory that holds `tlsanalyzer`:

```bash
# Scan a domain you own or have permission to test
./tlsanalyzer yourdomain.com
```

Expected output: Security grade, quantum risk score, CNSA 2.0 timeline.

Sample terminal output:

```
═══════════════════════════════════════════════════════════════
  QRAMM TLS Analyzer - Quantum-Ready Security Assessment
═══════════════════════════════════════════════════════════════

  Target: example.com
  IP: 172.66.147.243
  Scanned: 2026-10-18 13:31:29 MDT
  Duration: 126.759917ms

───────────────────────────────────────────────────────────────
  OVERALL GRADE
───────────────────────────────────────────────────────────────

  TLS Security:     F    (21/100)
  Quantum Ready:    Q
                    Q+ ready, Q partial, Q- limited, QV vulnerable

  Score Breakdown:
    Protocol Support     [████████░░░░░░░░░░░░] 10/25
    Cipher Strength      [████████████░░░░░░░░] 15/25
    Certificate          [████████████████████] 25/25
    Quantum Readiness    [████████████░░░░░░░░] 16/25
    Dimension subtotal                          66/100
    Vulnerability penalty                       -45  (1 HIGH x 15, 6 MEDIUM x 5)
    TLS Security score                          21/100

───────────────────────────────────────────────────────────────
  CNSA 2.0 COMPLIANCE TIMELINE
───────────────────────────────────────────────────────────────

    Current Phase:      New NSS Systems
    Timeline Score:     84/100
    Days to Deadline:   74
    Next Action:        Legacy protocol still enabled: TLS 1.2
    Scope:              milestone status reports whether this server can negotiate
                        the algorithms a milestone requires. A milestone can be met
                        while the server also still accepts weaker options, so a
                        policy evaluation of the same target year, which requires
                        every accepted protocol and cipher suite to qualify, can
                        report non-compliant against the same deadline. Read the
                        milestones for adoption and the policy evaluation for
                        exclusivity.

    Milestones:
      legend: ✓ met, ◐ partial, ○ in progress, ✗ not met, - not yet required
      ○ in progress, deadline passed: Preparation Phase (2025-12-31)
      ✓ met: New NSS Systems (2027-01-01)
      ◐ partial: TLS 1.3 Required (2030-01-02)
         └─ Legacy protocol still enabled: TLS 1.2
         └─ Legacy protocol still enabled: TLS 1.1
         └─ Legacy protocol still enabled: TLS 1.0
      - not yet required: Legacy System Update (2033-01-01)
         └─ PQC certificates not yet available
      - not yet required: Full PQC Transition (2035-01-01)
         └─ PQC certificates not yet available

───────────────────────────────────────────────────────────────
  CERTIFICATE
───────────────────────────────────────────────────────────────

    Status:      ✓ Valid
    Subject:     CN=example.com
    Issuer:      CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
    Valid:       2026-09-26 to 2026-12-25
    Key:         ECDSA 256-bit
    Signature:   ECDSA-SHA256
    SANs:        "example.com", "*.example.com"
    Name check:  ✓ valid for example.com
    Chain trust: ✓ chains to a root this host trusts
    Quantum:     ✗ Quantum Vulnerable
```

Abridged by cutting whole sections, not by editing lines: the real report also
carries the CNSA 2.0 algorithm status listing, which gives one line per
algorithm and status with a count where several cipher suites share it, as in
`[transitional] symmetric: AES (9 cipher suites)`, plus the protocol, cipher
suite, quantum risk, vulnerability,
recommendation and scan coverage sections, and every enumerated key exchange
group and cipher suite.

Generated with `tlsanalyzer example.com --no-color` on the 0.5.0 build, and
re-checked against it line for line on 2026-10-18.

The score breakdown reconciles: the four dimensions total 66 of 100 points, the
vulnerability findings deduct 45, and the headline is 66 - 45 = 21.

Adding `--policy cnsa-2.0-2027` prints a second CNSA 2.0 verdict, which can
disagree with the timeline milestone above because the two have different
scope. Both print a scope note saying which question they answer.

## What it does

### Security Analysis

| Feature | Description |
|---------|-------------|
| **Protocol Analysis** | TLS 1.0, 1.1, 1.2, 1.3 version detection with deprecation warnings |
| **Cipher Suite Evaluation** | Strength assessment, forward secrecy verification, weak algorithm detection |
| **Certificate Analysis** | Name verification against the requested name, chain verification against the host trust store, validity, key strength, signature algorithm assessment |
| **Vulnerability Detection** | BEAST, POODLE, weak ciphers, expired certificates, and more |

### Quantum Readiness

| Feature | Description |
|---------|-------------|
| **Quantum Risk Scoring** | 0-100 score, weighted toward key exchange because that is the risk that applies retroactively |
| **Hybrid PQC Detection** | Detects the negotiated key exchange group, and probes which groups the server supports (see the limits below) |
| **HNDL Risk Assessment** | Evaluate exposure to harvest-now-decrypt-later attacks |
| **CNSA 2.0 Timeline** | Track compliance against NSA's post-quantum migration deadlines |

### Compliance & Reporting

| Feature | Description |
|---------|-------------|
| **Policy-as-Code** | Built-in and custom YAML policies for automated compliance checking |
| **CNSA 2.0 Timeline Tracking** | Milestones for 2025, 2027, 2030, 2033, 2035 |
| **Multiple Output Formats** | Text, JSON, SARIF, CycloneDX CBOM, HTML |
| **Batch Scanning** | Scan multiple targets with concurrency control |

### What it does not check

- Revocation is not checked. Check revocation separately.
- `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` are not probed, and the scan coverage note says so.
- Chain trust is judged by the scanning machine: an internal CA's certificate shows as untrusted unless that CA is installed there.
- Post-quantum certificate signatures (ML-DSA, SLH-DSA) are reported as unavailable rather than detected.

More on each of these limits, and how to confirm the two hybrid groups yourself: [docs/how-it-works.md](docs/how-it-works.md).

## Usage

### Output Formats

```bash
./tlsanalyzer yourdomain.com                              # Human-readable text (default)
./tlsanalyzer yourdomain.com --format json                # JSON output
./tlsanalyzer yourdomain.com --format html -o report.html # Standalone HTML report
./tlsanalyzer yourdomain.com --format cbom -o cbom.json   # CycloneDX CBOM
./tlsanalyzer yourdomain.com --format sarif -o scan.sarif # SARIF for GitHub Security
```

### Policy Evaluation

```bash
./tlsanalyzer policies                                    # List available policies
./tlsanalyzer print-policy strict > custom.yaml           # A valid starting point
./tlsanalyzer yourdomain.com --policy cnsa-2.0-2027       # CNSA 2.0 compliance check
./tlsanalyzer yourdomain.com --policy-file custom.yaml    # Custom policy file
```

A policy that is not satisfied exits 2, so `--policy` can gate a pipeline
directly. A policy file is validated before the scan runs, and one that cannot
be understood is refused rather than reported as compliant: unknown keys, a
missing `name`, and a policy with no rules are all errors. See
[docs/policies.md](docs/policies.md) for the schema.

### Policies

| Policy | Description |
|--------|-------------|
| `modern` | Modern TLS configuration for 2024+ |
| `strict` | Strict TLS 1.3-only configuration |
| `cnsa-2.0-2027` | CNSA 2.0 for new NSS systems (2027 deadline) |
| `cnsa-2.0-2030` | CNSA 2.0 with TLS 1.3 required |
| `cnsa-2.0-2035` | CNSA 2.0 full PQC transition |

### Batch Scanning

Put one host name, IP address or host:port on each line of the targets file.
Lines starting with `#` are skipped. Every line is checked before anything is
looked up, and a file with any other line is refused: the message gives the
line numbers and the reason, and never prints the lines themselves. A target
listed twice is scanned once.

A line whose host is a single word, such as `intranet` or `intranet:8443`, is
refused unless `--allow-single-label` is given, because a token or password on
a line by itself has the same shape: letters, digits, `-` and `_`, up to 63
characters. `localhost` is accepted without the flag, and a single word given
as the target on the command line is not refused. Only point `--targets` at a
file of host names.

A byte order mark at the start of the file is ignored. An IPv6 link-local
address keeps its zone, as in `[fe80::1%en0]:8443`, when the zone is an
interface name or number. With `--format json`, a run given more than one
target prints an array, also when the file names one target on several lines,
and a run given one target prints one object.

```bash
# Create targets file
echo "api.yourdomain.com
web.yourdomain.com
auth.yourdomain.com" > targets.txt

# Scan all targets
./tlsanalyzer --targets targets.txt --format html -o report.html
```

### More Options

```bash
./tlsanalyzer yourdomain.com:8443                         # Custom port
./tlsanalyzer 192.168.1.1 --sni yourdomain.com            # Custom SNI
./tlsanalyzer yourdomain.com --timeout 60                 # Custom timeout
./tlsanalyzer yourdomain.com --skip-vulns                 # Skip vulnerability checks
./tlsanalyzer yourdomain.com --skip-quantum               # Skip quantum assessment
```

## Documentation

- [docs/commands.md](docs/commands.md): the flags for a scan, the `policies`, `print-policy` and `version` commands, the exit codes, and the output formats.
- [docs/how-it-works.md](docs/how-it-works.md): how the name check and chain trust work, more on what the scan does not check, how both grades are scored, and how the code is laid out.
- [docs/policies.md](docs/policies.md): the built-in policies and the full schema for writing your own.
- [docs/cnsa-2.0-compliance.md](docs/cnsa-2.0-compliance.md): the CNSA 2.0 timeline, algorithm classes, and a migration plan.
- [docs/ci-cd-integration.md](docs/ci-cd-integration.md): GitHub Actions, GitLab CI, Jenkins, and Azure DevOps examples.
- [docs/install.md](docs/install.md): downloading a pre-built binary and checking it against `checksums.txt`.
- [docs/USE-CASES.md](docs/USE-CASES.md): why quantum readiness matters, the QRAMM toolkit, references and acknowledgments.
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup and guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>Built with purpose by <a href="https://csnp.org">CSNP</a></strong>
</p>

<p align="center">
  <a href="https://qramm.org">QRAMM</a> &bull;
  <a href="https://csnp.org">CSNP</a> &bull;
  <a href="https://github.com/csnp/qramm-tls-analyzer/issues">Report Bug</a> &bull;
  <a href="https://github.com/csnp/qramm-tls-analyzer/issues">Request Feature</a>
</p>
