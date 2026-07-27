# Changelog

All notable changes to QRAMM TLS Analyzer are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-27

This release fixes a defect that prevented the analyzer from ever reporting a
quantum-safe connection, along with several correctness problems found while
reproducing it. Reported in [#1](https://github.com/csnp/tls-analyzer/issues/1).

### Fixed

- **Post-quantum key exchange was never detected.** `parseKeyExchange` returned a
  hardcoded classical `X25519` for every TLS 1.3 connection, and `quantumSafe`
  was a constant `false` in three separate places. A server negotiating
  `X25519MLKEM768` was reported as quantum vulnerable, so no scan could ever
  produce a quantum-safe result. The scanner now reads the negotiated group from
  `tls.ConnectionState.CurveID` and recognizes `X25519MLKEM768`,
  `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`.
- **Certificate fingerprints were not hashes.** `sha256Fingerprint` returned
  `hex(der[:20]) + "..."` and `sha1Fingerprint` returned `hex(der[:10]) + "..."`,
  which are prefixes of the certificate itself. Both values began with the same
  DER header bytes and matched no real fingerprint. They are now genuine SHA-256
  and SHA-1 digests that agree with `openssl x509 -fingerprint`.
- **Elliptic curve key sizes reported as 0.** The public key type switch matched
  only types implementing `Size() int`, which excludes ECDSA and Ed25519, so
  every EC certificate reported `publicKeyBits: 0`. RSA, ECDSA, Ed25519, and ECDH
  keys now report correct sizes.
- **AES-128 cipher suites reported as 256-bit.** `strings.Contains(name, "256")`
  matched the `SHA256` suffix of `TLS_AES_128_GCM_SHA256` before the key size was
  considered. Encryption key size is now matched specifically.
- **Nondeterministic scan output.** Protocol probes ran concurrently and appended
  results in completion order while the code assumed declaration order, so the
  protocol list and the `preferred` marker varied between identical runs.
  Results are now written to a fixed index per version, and the preferred
  protocol is the highest supported one.
- **Reports carried the wrong version.** Generated SARIF, CBOM, and HTML reports
  recorded scanner version `0.1.0` regardless of the installed release. The
  binary's version is now stamped on results and injected at build time.

### Changed

- **Quantum risk is now weighted 80/20 toward key exchange, up from 60/40.**
  Under the old weighting, a server running the strongest configuration
  available today (hybrid ML-KEM key exchange with a classical certificate)
  scored 48/100, graded HIGH risk, and was advised to "begin hybrid PQC
  implementation", which it had already completed. No publicly trusted CA issues
  ML-DSA certificates, so the certificate dimension could not be improved by any
  operator at any price. Key exchange is also the only dimension that applies
  retroactively, through harvest-now-decrypt-later. The same server now scores
  64/100, grades MEDIUM, and is advised to track CA readiness.
- Recommended time-to-action is derived from the key exchange and certificate
  dimensions separately rather than from the combined score.
- Key exchange results now list every group the server supports, not only the
  one this client negotiated. The negotiated group is marked with `negotiated`.
- Connection probes honour the caller's context for cancellation.

### Added

- `scanWarnings` field on scan results, recording coverage limits such as key
  exchange groups the running build cannot offer, so an absent result is never
  mistaken for a negative one.
- Regression tests covering key exchange group mapping, cipher suite key sizes,
  fingerprint correctness, public key sizing, merge ordering determinism, and
  the quantum advice regression.

### Requirements

- Go 1.25 or later is now required, for `tls.ConnectionState.CurveID`. CI and
  release builds moved from Go 1.21 to Go 1.25.

[0.3.0]: https://github.com/csnp/tls-analyzer/releases/tag/v0.3.0
