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
  <a href="#usage">Usage</a> &bull;
  <a href="#output-formats">Output Formats</a> &bull;
  <a href="#policies">Policies</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

**QRAMM TLS Analyzer** is an open-source command-line tool that performs comprehensive TLS security analysis with a focus on **post-quantum cryptography (PQC) readiness**. As quantum computing advances, organizations must prepare their cryptographic infrastructure for the post-quantum era. This tool helps you understand your current TLS posture and provides actionable guidance for CNSA 2.0 compliance.

Part of the [QRAMM (Quantum Readiness Assurance Maturity Model)](https://qramm.org) toolkit, developed by the [Cyber Security Non-Profit (CSNP)](https://csnp.org).

> **Responsible use warning**
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
| **Certificate Analysis** | Name verification against the requested name, chain verification against the host trust store, validity, key strength, signature algorithm assessment |
| **Vulnerability Detection** | BEAST, POODLE, weak ciphers, expired certificates, and more |

The scan handshakes with verification disabled on purpose, so it can connect to
and describe a certificate a verifying client would refuse. The two checks that
disabling verification would otherwise skip are run separately and reported
separately, whatever their outcome including when they did not run:

- **Name check.** The certificate has to be valid for the name that was actually
  requested, which is the `--sni` value when one is given and the target
  otherwise. When the two differ, the report says which name was verified.
- **Chain trust.** The presented chain has to build to a root the scanning
  machine trusts, for server authentication. The question it answers is whether a
  client on this machine would accept the chain, so the verdict is
  machine-dependent by design: a certificate from an internal CA is reported
  untrusted unless that CA is installed locally, and a scan warning says so.

  Every certificate in the chain is covered, not just the leaf. When the
  verifier rejects the chain over a validity window and the leaf is inside its
  own, the reason names the offending certificate and which end of its window
  failed, because every other field in the report describes the leaf and the leaf
  is healthy in that case. Two limits are worth stating plainly. Where the
  platform reports only that the chain is untrusted, which macOS and Windows may
  do because they answer through the system verifier rather than Go's, the check
  still fails but the reason is the platform's own and need not name a
  certificate. And where the platform builds a valid path of its own, by
  substituting a stored intermediate or fetching one, it does not reject the
  chain at all, so no window is inspected and the chain is reported as trusted.
  That is the honest answer to the question this check asks, since a client on
  that machine would also accept it, but it means a chain another client rejects
  can pass here.

Either check failing scores the certificate dimension zero, for the same reason
expiry does: no client will use the certificate.

Revocation is not checked. This scanner does not fetch CRLs or query OCSP, so a
chain reported as trusted may still have been revoked, and a scan warning says
so. Check revocation separately.

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
./tlsanalyzer print-policy strict > custom.yaml           # A valid starting point
./tlsanalyzer yourdomain.com --policy cnsa-2.0-2027       # CNSA 2.0 compliance check
./tlsanalyzer yourdomain.com --policy-file custom.yaml    # Custom policy file
```

A policy that is not satisfied exits 2, so `--policy` can gate a pipeline
directly. A policy file is validated before the scan runs, and one that cannot
be understood is refused rather than reported as compliant: unknown keys, a
missing `name`, and a policy with no rules are all errors. See
[docs/policies.md](docs/policies.md) for the schema.

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
  IP: 104.20.23.154
  Scanned: 2026-07-30 14:11:25 MDT
  Duration: 143.383583ms

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
    Days to Deadline:   154
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
      legend: ✓ met, ◐ partial, ○ in progress, ✗ not met, — not yet required
      ○ Preparation Phase (2025-12-31)
      ✓ New NSS Systems (2027-01-01)
      ◐ TLS 1.3 Required (2030-01-02)
         └─ Legacy protocol still enabled: TLS 1.2
         └─ Legacy protocol still enabled: TLS 1.1
         └─ Legacy protocol still enabled: TLS 1.0
      — Legacy System Update (2033-01-01)
         └─ PQC certificates not yet available
      — Full PQC Transition (2035-01-01)
         └─ PQC certificates not yet available

───────────────────────────────────────────────────────────────
  CERTIFICATE
───────────────────────────────────────────────────────────────

    Status:      ✓ Valid
    Subject:     CN=example.com
    Issuer:      CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
    Valid:       2026-07-29 to 2026-10-27
    Key:         ECDSA 256-bit
    Signature:   ECDSA-SHA256
    SANs:        example.com, *.example.com
    Name check:  ✓ valid for example.com
    Chain trust: ✓ chains to a root this host trusts
    Quantum:     ✗ Quantum Vulnerable
```

Abridged by cutting whole sections, not by editing lines: the real report also
carries the CNSA 2.0 algorithm status listing, which repeats one line per
accepted suite, plus the protocol, cipher suite, quantum risk, vulnerability,
recommendation and scan coverage sections, and every enumerated key exchange
group and cipher suite. Generated with `tlsanalyzer example.com --no-color` on
the 0.4.0 build.

The score breakdown reconciles: the four dimensions total 66 of 100 points, the
vulnerability findings deduct 45, and the headline is 66 - 45 = 21. Adding
`--policy cnsa-2.0-2027` prints a second CNSA 2.0 verdict, which can disagree
with the timeline milestone above because the two have different scope. Both
print a scope note saying which question they answer.

Other formats: `--format json` for automation, `--format cbom` for [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/), `--format html` for shareable reports, `--format sarif` for GitHub Security.

## Policies

| Policy | Description |
|--------|-------------|
| `modern` | Modern TLS configuration for 2024+ |
| `strict` | Strict TLS 1.3-only configuration |
| `cnsa-2.0-2027` | CNSA 2.0 for new NSS systems (2027 deadline) |
| `cnsa-2.0-2030` | CNSA 2.0 with TLS 1.3 required |
| `cnsa-2.0-2035` | CNSA 2.0 full PQC transition |

Custom policies are YAML. `tlsanalyzer print-policy <name>` prints any built-in
policy in exactly the shape `--policy-file` accepts, which is the recommended
starting point: keys the schema does not define are refused rather than ignored.
`extends` inherits a built-in policy, and every key the file sets overrides the
inherited one. See [docs/policies.md](docs/policies.md) for the full schema.

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
| **B** | 75-84 | Good with minor improvements needed |
| **C** | 60-74 | Adequate but significant improvements recommended |
| **D** | 40-59 | Poor configuration, security issues present |
| **F** | 0-39 | Failing, critical vulnerabilities |

The score is the four dimensions above, each worth 25 points and normalised to
100, less a vulnerability penalty of 30 points per CRITICAL finding, 15 per HIGH
and 5 per MEDIUM. LOW and INFO findings do not move it. The report prints the
subtotal, the penalty and the final score as separate lines so the arithmetic can
be checked. A dimension that was skipped with `--skip-quantum` contributes
neither points nor maximum, so the subtotal is normalised over what actually ran.
Skipping the vulnerability checks with `--skip-vulns` leaves the penalty
unmeasured rather than zero, so the score is then reported as an upper bound and
is not comparable with a full scan's.

TLS 1.3 alone earns the full protocol dimension. TLS 1.2 alongside it is neither
a bonus nor a penalty, so disabling TLS 1.2 does not cost points, and only
deprecated versions deduct. Before 0.4.0 a TLS 1.3-only server was capped at 15
of 25, which penalised the configuration the `strict` and `cnsa-2.0-2030`
policies require.

### Quantum Readiness Grade

Derived from the 0-100 quantum risk score, which is weighted 80 percent key
exchange and 20 percent certificate.

| Grade | Quantum score | Description |
|-------|---------------|-------------|
| **Q+** | 80-100 | Ready: a full PQC key exchange, or hybrid plus a PQC certificate |
| **Q** | 50-79 | Partial: hybrid PQC key exchange in place |
| **Q-** | 20-49 | Limited post-quantum protection |
| **QV** | 0-19 | Vulnerable: classical cryptography only |

The weighting decides what reaches Q+. A full PQC key exchange scores the key
exchange term outright, which is 80 of the 100 on its own, so it reaches Q+ with
an ordinary classical certificate and no CA involvement at all. Hybrid key
exchange scores 80 of that term rather than all of it, so hybrid with a classical
certificate scores 64 and correctly reports Q; reaching Q+ that way needs a
post-quantum certificate, and no publicly trusted CA issues one yet.

In practice almost every server that has deployed post-quantum key exchange has
deployed it as hybrid, because a PQC-only key exchange cannot talk to classical
clients. So Q is the grade a well-configured public server reports today, and it
is the best posture most operators can reach.

## CLI Reference

```
USAGE:
  tlsanalyzer [target] [flags]
  tlsanalyzer [command]

COMMANDS:
  policies      List available security policies
  print-policy  Print a built-in policy as YAML, to copy as a starting point
  version       Print version information

FLAGS:
  -f, --format string      Output format: text, json, sarif, cbom, html (default "text")
  -o, --output string      Output file (default: stdout)
  -t, --timeout int        Connection timeout in seconds (default 30)
  -p, --port int           Target port, 1-65535, overrides a port in the
                           target (default 443)
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

EXIT CODES:
  0  scanned, and any policy applied was fully evaluated and satisfied
  1  the scan could not be completed
  2  a policy was applied and the target did not satisfy it, or the policy
     could not be fully evaluated
```

`--policy` and `--policy-file` both name a policy, so passing both is an error
rather than one silently winning.

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
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) - Module-Lattice Key Encapsulation
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) - Module-Lattice Digital Signatures
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) - Stateless Hash-Based Digital Signatures
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
