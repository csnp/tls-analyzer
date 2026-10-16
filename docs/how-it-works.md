# How the scan works

This page holds the detail behind the README: what each check does and where
it stops, how the two grades are worked out, and how the code is laid out.

## What the scan checks

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
| **Hybrid PQC Detection** | Detects the negotiated key exchange group, and separately probes which groups the server supports. `X25519MLKEM768` is probed; the two NIST P-curve hybrids `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` are **not**, because this build's TLS stack cannot offer them (see the note below) |
| **HNDL Risk Assessment** | Evaluate exposure to harvest-now-decrypt-later attacks |
| **CNSA 2.0 Timeline** | Track compliance against NSA's post-quantum migration deadlines |

`SecP256r1MLKEM768` and `SecP384r1MLKEM1024` are not probed and are not
reported, even by a server that offers them. Measured against an OpenSSL 3.6.1
server offering all three hybrid groups: `openssl s_client` negotiates each of
the three, and this tool reports only `X25519MLKEM768` and `X25519`. A server
offering the two P-curve hybrids and nothing else cannot be scanned at all. The
scan says nothing either way about them and, unlike the other enumeration limits
this tool discloses, prints no coverage note. Confirm those two groups with
`openssl s_client -connect host:443 -groups SecP384r1MLKEM1024`. This is
recorded as a defect rather than a design limit.

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

## Grading System

The four dimensions named below are the ones in the report's score breakdown:
protocol support, cipher strength, certificate and quantum readiness. The
README's sample report shows them.

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
│   │   ├── sanitize_result.go # Scrubs untrusted text once, at the renderer door
│   │   └── text.go           # Terminal output with colors
│   ├── sanitize/
│   │   └── sanitize.go       # Control-character scrubbing and length bounding
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
