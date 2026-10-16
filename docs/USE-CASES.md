# Background: quantum readiness and QRAMM

Why post-quantum readiness is worth checking now, the QRAMM framework this tool
belongs to, the standards it follows, and the people and projects it builds on.

## Why Quantum Readiness Matters

- **Harvest Now, Decrypt Later (HNDL)**: Adversaries are collecting encrypted data today to decrypt once quantum computers become available
- **CNSA 2.0 Deadlines**: NSA's timeline requires hybrid PQC for new systems by 2027 and full transition by 2035
- **Long Migration Cycles**: Cryptographic migrations typically take 5-10 years to complete
- **Regulatory Pressure**: Government agencies and regulated industries must demonstrate quantum readiness

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

## References

- [NSA CNSA 2.0 Guidance](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) - Commercial National Security Algorithm Suite 2.0
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - PQC Standardization
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) - Module-Lattice Key Encapsulation
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) - Module-Lattice Digital Signatures
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) - Stateless Hash-Based Digital Signatures
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/rfc8446/) - Transport Layer Security 1.3
- [RFC 8996: Deprecating TLS 1.0 and 1.1](https://datatracker.ietf.org/doc/rfc8996/)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) - Cryptographic Bill of Materials

## Acknowledgments

- NSA's CNSA 2.0 guidance for post-quantum cryptography standards
- NIST for PQC algorithm standardization (ML-KEM, ML-DSA, SLH-DSA)
- The Go team for excellent TLS library support
- CycloneDX for the CBOM specification
- Our amazing contributors and the open-source community
