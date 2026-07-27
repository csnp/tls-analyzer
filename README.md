<h1 align="center">QRAMM TLS Analyzer</h1>

<p align="center">
  <strong>Quantum-Ready TLS Security Assessment Tool</strong>
</p>

<p align="center">
  <a href="https://github.com/csnp/qramm-tls-analyzer/actions"><img src="https://github.com/csnp/qramm-tls-analyzer/workflows/CI/badge.svg" alt="CI Status"></a>
  <a href="https://goreportcard.com/report/github.com/csnp/qramm-tls-analyzer"><img src="https://goreportcard.com/badge/github.com/csnp/qramm-tls-analyzer?v=2" alt="Go Report Card"></a>
  <a href="https://pkg.go.dev/github.com/csnp/qramm-tls-analyzer"><img src="https://pkg.go.dev/badge/github.com/csnp/qramm-tls-analyzer.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#installation">Installation</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#output-formats">Output Formats</a> &bull;
  <a href="#policies">Policies</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

**QRAMM TLS Analyzer** is an open-source command-line tool that performs comprehensive TLS security analysis with a focus on **post-quantum cryptography (PQC) readiness**. As quantum computing advances, organizations must prepare their cryptographic infrastructure for the post-quantum era. This tool helps you understand your current TLS posture and provides actionable guidance for CNSA 2.0 compliance.

Part of the [QRAMM (Quantum Readiness Assurance Maturity Model)](https://qramm.org) toolkit, developed by the [Cyber Security Non-Profit (CSNP)](https://csnp.org).

> **⚠️ Responsible Use Warning**
>
> This tool performs active network connections to analyze TLS configurations. **Only scan systems and domains you own or have explicit written authorization to test.** Unauthorized scanning may violate laws and regulations in your jurisdiction. The authors assume no liability for misuse of this tool.

### Why Quantum Readiness Matters

- **Harvest Now, Decrypt Later (HNDL)**: Adversaries are collecting encrypted data today to decrypt once quantum computers become available
- **CNSA 2.0 Deadlines**: NSA's timeline requires hybrid PQC for new systems by 2027 and full transition by 2035
- **Long Migration Cycles**: Cryptographic migrations typically take 5-10 years to complete
- **Regulatory Pressure**: Government agencies and regulated industries must demonstrate quantum readiness

## Quick Start

### Option 1: Build from Source

Requires Go 1.23+ ([install Go](https://go.dev/doc/install))

Copy and paste this entire block:

```bash
git clone https://github.com/csnp/qramm-tls-analyzer.git
cd qramm-tls-analyzer
go build -o tlsanalyzer ./cmd/tlsanalyzer
sudo mv tlsanalyzer /usr/local/bin/
cd ..
tlsanalyzer version
```

### Option 2: Download Binary

Download pre-built binaries from [Releases](https://github.com/csnp/qramm-tls-analyzer/releases).

### Run Your First Scan

```bash
# Scan a domain you own or have permission to test
tlsanalyzer yourdomain.com
```

Expected output: Security grade, quantum risk score, CNSA 2.0 timeline.

## Features

### Security Analysis

| Feature | Description |
|---------|-------------|
| **Protocol Analysis** | TLS 1.0, 1.1, 1.2, 1.3 version detection with deprecation warnings |
| **Cipher Suite Evaluation** | Strength assessment, forward secrecy verification, weak algorithm detection |
| **Certificate Analysis** | Validity, chain verification, key strength, signature algorithm assessment |
| **Vulnerability Detection** | BEAST, POODLE, weak ciphers, expired certificates, and more |

### Quantum Readiness

| Feature | Description |
|---------|-------------|
| **Quantum Risk Scoring** | 0-100 score, weighted toward key exchange because that is the risk that applies retroactively |
| **Hybrid PQC Detection** | Detects the negotiated key exchange group and separately probes which groups the server supports: `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` |
| **HNDL Risk Assessment** | Evaluate exposure to harvest-now-decrypt-later attacks |
| **CNSA 2.0 Timeline** | Track compliance against NSA's post-quantum migration deadlines |

Post-quantum certificate signatures (ML-DSA, SLH-DSA) are reported as unavailable
rather than detected. No publicly trusted CA issues them yet, so a classical
certificate is not counted as a failure an operator could act on today. The
quantum score is weighted 80 percent key exchange and 20 percent certificate for
the same reason: recorded traffic is decrypted retroactively once a quantum
computer exists, while a signature cannot be forged after the fact.

### Compliance & Reporting

| Feature | Description |
|---------|-------------|
| **Policy-as-Code** | Built-in and custom YAML policies for automated compliance checking |
| **CNSA 2.0 Timeline Tracking** | Milestones for 2025, 2027, 2030, 2033, 2035 |
| **Multiple Output Formats** | Text, JSON, SARIF, CycloneDX CBOM, HTML |
| **Batch Scanning** | Scan multiple targets with concurrency control |

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
./tlsanalyzer yourdomain.com --policy cnsa-2.0-2027       # CNSA 2.0 compliance check
./tlsanalyzer yourdomain.com --policy-file custom.yaml    # Custom policy file
```

### Batch Scanning

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

## Example Output

Sample terminal output:

```
═══════════════════════════════════════════════════════════════
  QRAMM TLS Analyzer - Quantum-Ready Security Assessment
═══════════════════════════════════════════════════════════════

  Target: example.com
  IP: 172.66.147.243
  Scanned: 2026-07-27 13:38:45 MDT
  Duration: 80.176667ms

───────────────────────────────────────────────────────────────
  OVERALL GRADE
───────────────────────────────────────────────────────────────

  TLS Security:     D    (51/100)
  Quantum Ready:    Q

  Score Breakdown:
    Protocol Support     [████████░░░░░░░░░░░░] 10/25
    Cipher Strength      [████████████████░░░░] 20/25
    Certificate          [████████████████████] 25/25
    Quantum Readiness    [████████████░░░░░░░░] 16/25

───────────────────────────────────────────────────────────────
  POLICY EVALUATION
───────────────────────────────────────────────────────────────

    Policy:     cnsa-2.0-2027
    Status:     ✗ NON-COMPLIANT
    Score:      70/100

    Violations (2)
      • [HIGH] Cipher suite key size below minimum
        Expected: >= 256 bits | Actual: 128 bits (TLS_AES_128_GCM_SHA256)
      • [HIGH] ECC key size below minimum
        Expected: >= 384 bits | Actual: 256 bits

───────────────────────────────────────────────────────────────
  CNSA 2.0 COMPLIANCE TIMELINE
───────────────────────────────────────────────────────────────

    Current Phase:      New NSS Systems
    Timeline Score:     84/100
    Days to Deadline:   157
    Next Action:        Legacy protocol still enabled: TLS 1.2

    Milestones:
      ○ Preparation Phase (2025-12-31)
      ✓ New NSS Systems (2027-01-01)
      ◐ TLS 1.3 Required (2030-01-02)
         └─ Legacy protocol still enabled: TLS 1.2
      — Legacy System Update (2033-01-01)
         └─ PQC certificates not yet available
      — Full PQC Transition (2035-01-01)
         └─ PQC certificates not yet available

    Algorithm Status:
      [approved    ] key-exchange: X25519MLKEM768
      [transitional] key-exchange: X25519
      [transitional] signature: ECDSA-SHA256
      [deprecated  ] signature-key: ECDSA
               Replace with: ML-DSA certificates (when available)
```

Other formats: `--format json` for automation, `--format cbom` for [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/), `--format html` for shareable reports, `--format sarif` for GitHub Security.

## Policies

| Policy | Description |
|--------|-------------|
| `modern` | Modern TLS configuration for 2024+ |
| `strict` | Strict TLS 1.3-only configuration |
| `cnsa-2.0-2027` | CNSA 2.0 for new NSS systems (2027 deadline) |
| `cnsa-2.0-2030` | CNSA 2.0 with TLS 1.3 required |
| `cnsa-2.0-2035` | CNSA 2.0 full PQC transition |

Custom policies can be created in YAML format. See [docs/policies.md](docs/policies.md) for details.

## CNSA 2.0 Timeline

The tool tracks compliance against NSA's Commercial National Security Algorithm Suite 2.0 timeline:

| Milestone | Deadline | Requirements |
|-----------|----------|--------------|
| **Preparation Phase** | Dec 2025 | Begin PQC integration planning, inventory cryptographic assets |
| **New NSS Systems** | Jan 2027 | ML-KEM for key exchange, ML-DSA/SLH-DSA for signatures, AES-256, SHA-384+ |
| **TLS 1.3 Required** | Jan 2030 | TLS 1.3 mandatory, hybrid PQC required, RSA/ECDH no longer acceptable |
| **Legacy System Update** | Jan 2033 | Complete migration of all existing systems, PQC certificates deployed |
| **Full PQC Transition** | Jan 2035 | Pure PQC (no hybrid required), classical algorithms fully retired |

### Algorithm Classification

| Status | Description | Examples |
|--------|-------------|----------|
| **Approved** | CNSA 2.0 approved | ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87, SLH-DSA, AES-256, SHA-384, SHA-512 |
| **Transitional** | Allowed until deadline | RSA-3072, RSA-4096, ECDSA-P384, ECDH-P384, X25519 (hybrid only), SHA-256 |
| **Deprecated** | Phase out immediately | RSA-2048, ECDSA-P256, ECDH-P256 |
| **Prohibited** | Never use | 3DES, RC4, SHA-1, MD5 |

## Grading System

### TLS Security Grade

| Grade | Score | Description |
|-------|-------|-------------|
| **A+** | 95-100 | Exceptional security with quantum readiness |
| **A** | 85-94 | Excellent configuration |
| **B** | 70-84 | Good with minor improvements needed |
| **C** | 55-69 | Adequate but significant improvements recommended |
| **D** | 40-54 | Poor configuration, security issues present |
| **F** | 0-39 | Failing, critical vulnerabilities |

### Quantum Readiness Grade

| Grade | Description |
|-------|-------------|
| **Q+** | Full PQC ready (ML-KEM key exchange + ML-DSA certificates) |
| **Q** | Hybrid PQC key exchange enabled |
| **Q-** | Partially quantum-ready |
| **QV** | Quantum vulnerable (classical cryptography only) |

## CLI Reference

```
USAGE:
  tlsanalyzer [target] [flags]
  tlsanalyzer [command]

COMMANDS:
  policies    List available security policies
  version     Print version information

FLAGS:
  -f, --format string      Output format: text, json, sarif, cbom, html (default "text")
  -o, --output string      Output file (default: stdout)
  -t, --timeout int        Connection timeout in seconds (default 30)
  -p, --port int           Target port (default 443)
      --sni string         Server Name Indication (SNI)
      --no-color           Disable colored output
      --compact            Compact JSON output
      --skip-vulns         Skip vulnerability checks
      --skip-quantum       Skip quantum risk assessment
      --skip-cnsa2         Skip CNSA 2.0 compliance analysis
      --policy string      Apply a security policy
      --policy-file string Path to custom policy YAML file
      --targets string     File containing list of targets
  -c, --concurrency int    Concurrent scans for batch mode (default 10)
  -h, --help              Help for tlsanalyzer
```

## CI/CD Integration

See [docs/ci-cd-integration.md](docs/ci-cd-integration.md) for GitHub Actions, GitLab CI, Jenkins, and Azure DevOps examples.

## Architecture

```
qramm-tls-analyzer/
├── cmd/
│   └── tlsanalyzer/
│       └── main.go           # CLI entry point, flag parsing, batch scanning
├── internal/
│   ├── analyzer/
│   │   ├── cnsa2.go          # CNSA 2.0 compliance analysis
│   │   └── policy.go         # Policy-as-code evaluation
│   ├── reporter/
│   │   ├── cbom.go           # CycloneDX CBOM output
│   │   ├── html.go           # HTML report generation
│   │   ├── json.go           # JSON output
│   │   ├── sarif.go          # SARIF output
│   │   └── text.go           # Terminal output with colors
│   └── scanner/
│       ├── scanner.go        # Core TLS scanning logic
│       ├── quantum.go        # PQC risk assessment
│       ├── vulnerabilities.go # Vulnerability detection
│       ├── grade.go          # Grading system
│       └── recommendations.go # Actionable recommendations
└── pkg/
    └── types/
        ├── result.go         # Scan result types
        ├── policy.go         # Policy definitions
        ├── cbom.go           # CycloneDX CBOM types
        └── compliance.go     # Compliance framework types
```

## About QRAMM

**QRAMM (Quantum Readiness Assurance Maturity Model)** is an evidence-based framework designed to help enterprises systematically prepare for the quantum computing threat to current cryptographic systems. QRAMM provides structured evaluation across quantum readiness dimensions.

Visit [qramm.org](https://qramm.org) to learn more about:
- Quantum readiness assessment
- Migration planning resources
- Implementation guidance
- Industry benchmarks

### QRAMM Toolkit

This analyzer is part of the QRAMM open-source toolkit:

| Tool | Description |
|------|-------------|
| **TLS Analyzer** | TLS/SSL configuration analysis with quantum readiness (this tool) |
| **[CryptoScan](https://github.com/csnp/qramm-cryptoscan)** | Cryptographic discovery scanner for codebases |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## References

- [NSA CNSA 2.0 Guidance](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) - Commercial National Security Algorithm Suite 2.0
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - PQC Standardization
- [FIPS 203: ML-KEM](https://csrc.nist.gov/publications/detail/fips/203/final) - Module-Lattice Key Encapsulation
- [FIPS 204: ML-DSA](https://csrc.nist.gov/publications/detail/fips/204/final) - Module-Lattice Digital Signatures
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/publications/detail/fips/205/final) - Stateless Hash-Based Digital Signatures
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/rfc8446/) - Transport Layer Security 1.3
- [RFC 8996: Deprecating TLS 1.0 and 1.1](https://datatracker.ietf.org/doc/rfc8996/)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) - Cryptographic Bill of Materials

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- NSA's CNSA 2.0 guidance for post-quantum cryptography standards
- NIST for PQC algorithm standardization (ML-KEM, ML-DSA, SLH-DSA)
- The Go team for excellent TLS library support
- CycloneDX for the CBOM specification
- Our amazing contributors and the open-source community

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
