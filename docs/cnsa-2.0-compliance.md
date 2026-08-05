# CNSA 2.0 Compliance Guide

This guide explains the CNSA 2.0 (Commercial National Security Algorithm Suite 2.0) requirements and how QRAMM TLS Analyzer helps you achieve compliance.

## What is CNSA 2.0?

CNSA 2.0 is the NSA's guidance for transitioning to quantum-resistant cryptographic algorithms. It establishes a timeline for adopting post-quantum cryptography (PQC) to protect National Security Systems (NSS) against the future threat of quantum computers.

## Timeline Overview

| Milestone | Deadline | Key Requirements |
|-----------|----------|------------------|
| **Preparation Phase** | December 2025 | Inventory cryptographic assets, begin PQC integration planning |
| **New NSS Systems** | January 2027 | ML-KEM for key exchange, ML-DSA/SLH-DSA for signatures |
| **TLS 1.3 Required** | January 2030 | TLS 1.3 mandatory, hybrid PQC required |
| **Legacy System Update** | January 2033 | Complete migration of existing systems |
| **Full PQC Transition** | January 2035 | Pure PQC (no hybrid), classical algorithms retired |

## Algorithm Requirements

### Key Exchange

| Algorithm | Status | Notes |
|-----------|--------|-------|
| ML-KEM-768 | **Approved** | Minimum for new systems by 2027 |
| ML-KEM-1024 | **Approved** | Higher security level |
| X25519MLKEM768 | **Approved** | Hybrid for TLS 1.3 |
| SecP384r1MLKEM1024 | **Approved** | Hybrid for TLS 1.3 |
| ECDH-P384 | Transitional | Phase out by 2030 |
| ECDH-P256 | Deprecated | Phase out immediately |
| RSA-3072+ | Transitional | Phase out by 2030 |

### Digital Signatures

| Algorithm | Status | Notes |
|-----------|--------|-------|
| ML-DSA-65 | **Approved** | Module-Lattice Digital Signature |
| ML-DSA-87 | **Approved** | Higher security level |
| SLH-DSA-SHA2-128s | **Approved** | Stateless Hash-Based |
| SLH-DSA-SHAKE-128s | **Approved** | Stateless Hash-Based |
| ECDSA-P384 | Transitional | Phase out by 2030 |
| RSA-3072+ | Transitional | Phase out by 2030 |

### Symmetric Encryption

| Algorithm | Status | Notes |
|-----------|--------|-------|
| AES-256 | **Approved** | Required |
| AES-128 | Transitional | Phase out by 2030 |

### Hash Functions

| Algorithm | Status | Notes |
|-----------|--------|-------|
| SHA-384 | **Approved** | Minimum for new systems |
| SHA-512 | **Approved** | Preferred |
| SHA-256 | Transitional | Phase out by 2030 |
| SHA-1 | **Prohibited** | Never use |

## Using TLS Analyzer for CNSA 2.0

### Evaluate Against 2027 Requirements

```bash
tlsanalyzer example.com --policy cnsa-2.0-2027
```

This checks:
- ML-KEM hybrid key exchange is available
- AES-256 cipher suites are negotiated
- SHA-384+ hash functions are used
- TLS 1.2+ is supported

### Evaluate Against 2030 Requirements

```bash
tlsanalyzer example.com --policy cnsa-2.0-2030
```

This checks:
- TLS 1.3 is required
- Hybrid PQC key exchange is mandatory
- RSA/ECDH without PQC is rejected
- All deprecated algorithms are banned

### Evaluate Against 2035 Requirements

```bash
tlsanalyzer example.com --policy cnsa-2.0-2035
```

This checks:
- Pure PQC key exchange (no hybrid required)
- ML-DSA certificates are used
- All classical algorithms are retired

## Understanding the Output

### Timeline Score

The CNSA 2.0 Timeline Score (0-100) indicates how well your configuration meets the next deadline:

| Score | Meaning |
|-------|---------|
| 90-100 | Excellent - Ready for next milestone |
| 70-89 | Good - Minor improvements needed |
| 50-69 | Moderate - Significant work required |
| 25-49 | Poor - Major changes needed |
| 0-24 | Critical - Immediate action required |

### Milestone Status

Each milestone shows one of these statuses:

The values below are what the JSON emits, verbatim. They are lowercase and
hyphenated, and a consumer filtering on them must match these exact strings.

- `compliant` - all requirements met
- `partial` - some requirements met
- `non-compliant` - requirements not met
- `in-progress` - the deadline is ahead and the requirements are partly met
- `not-applicable` - the deadline is not yet relevant to this system

## Migration Strategy

### Phase 1: Assessment (Now - Dec 2025)

1. **Inventory cryptographic assets**
   ```bash
   tlsanalyzer --targets hosts.txt --format cbom -o crypto-inventory.json
   ```

2. **Identify quantum-vulnerable systems**
   ```bash
   tlsanalyzer --targets hosts.txt --format json | jq '.[] | select(.quantumRisk.level == "CRITICAL")'
   ```

3. **Establish baseline**
   ```bash
   tlsanalyzer --targets hosts.txt --policy cnsa-2.0-2027 --format json -o baseline.json
   ```

### Phase 2: Preparation (2025-2027)

1. Upgrade to TLS 1.3 where possible
2. Test hybrid PQC key exchange in staging
3. Update certificate infrastructure for larger keys
4. Train staff on PQC concepts

### Phase 3: Implementation (2027-2030)

1. Enable hybrid PQC key exchange on new systems
2. Migrate existing systems to TLS 1.3
3. Update cipher suite ordering
4. Monitor compliance continuously

### Phase 4: Completion (2030-2035)

1. Transition to pure PQC where supported
2. Retire hybrid configurations
3. Update to ML-DSA certificates
4. Retire all classical algorithms

## Continuous Monitoring

Set up automated compliance checking:

```yaml
# .github/workflows/cnsa2-compliance.yml
name: CNSA 2.0 Compliance Check

on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: Install TLS Analyzer
        run: go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest

      - name: Check CNSA 2.0 Compliance
        run: |
          tlsanalyzer api.example.com --policy cnsa-2.0-2027 --format json | \
            jq -e '.policyResult.compliant == true' || \
            echo "::warning::CNSA 2.0 compliance check failed"
```

## References

- [NSA CNSA 2.0 Guidance](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
