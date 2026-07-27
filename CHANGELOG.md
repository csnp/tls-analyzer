# Changelog

All notable changes to QRAMM TLS Analyzer are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-27

### Fixed (found by the second pre-release fresh-user pass)

- **`--skip-quantum` fabricated a negative post-quantum finding.** Excluding the
  assessment from the grade was not enough: the report still printed
  `Quantum Ready: QV`, `✗ Hybrid PQC Key Exchange`, `hybridPqcReady: false`, and
  a priority-1 recommendation to enable hybrid key exchange, for servers that
  demonstrably negotiate `X25519MLKEM768`, while the CNSA section of the same
  report listed that group as approved. A suppressed check now produces no
  quantum findings, no quantum recommendations, and a quantum grade of
  "not assessed" rather than "quantum vulnerable". Not measured is not absent.
- **IPv6 targets could not be scanned.** Connection addresses were built with
  `fmt.Sprintf("%s:%d", host, port)`, producing `::1:19502` instead of
  `[::1]:19502`, so every IPv6 target failed as "unreachable" and was
  indistinguishable from a real finding. Verified fixed against a local TLS
  server on `[::1]` that OpenSSL also reaches.
- **Scan coverage warnings were invisible in text output**, the default format.
  The caveats existed only in JSON, which is exactly where they were not needed.
  Text reports now carry a "Scan coverage" section.
- **The cipher enumeration warning overstated its own completeness.** It claimed
  "TLS 1.2 and earlier suites are enumerated in full", but Go does not implement
  the CBC-SHA256 and CBC-SHA384 families, so a server can accept suites that do
  not appear. The warning now states that limit instead of denying it.
- **An unknown `--format` silently produced text with exit 0.** A pipeline
  asking for `--format JSON` (wrong case) received a text report and a success
  code. Unknown formats are now rejected with the list of supported values.

### Fixed (found by the pre-release fresh-user test)

- **`--port` was declared and documented but never read.** `tlsanalyzer host -p 8443`
  silently scanned port 443 and reported a confident grade for a port the user
  never asked about. Only the `host:port` form worked. The flag now applies when
  explicitly passed, and overrides a port already present in the target.
- **Unreachable hosts produced a fabricated report.** A name that did not resolve,
  or a port that refused the connection, yielded `F (0/100)`, `Risk: CRITICAL`,
  `HNDL: CRITICAL - no forward secrecy`, and exit code 0, with no error field
  anywhere. A host that was never contacted was indistinguishable from one
  measured to be insecure, and in a `--targets` sweep every typo became a
  confident failing row. Both cases are now errors with a non-zero exit.
- **Only the negotiated cipher suite was reported.** The scanner asked once and
  presented the answer as the server's full cipher configuration, which produced
  the grade rationale "all ciphers have forward secrecy" after a single
  handshake, and a false CNSA 2.0 violation ("key size below minimum, 128 bits")
  against servers that also offer AES-256. Cipher suites for TLS 1.2 and earlier
  are now enumerated by probing each one. TLS 1.3 suites cannot be enumerated
  this way, because Go's TLS stack ignores per-suite configuration for TLS 1.3,
  and that limitation is now stated in `scanWarnings` rather than left implicit.
- **`--targets ... --format json` emitted invalid JSON**, as concatenated objects
  rather than an array. This is a documented example in `--help`, and every
  strict parser rejected it. Batch mode now emits a single JSON array.
- **`--skip-quantum` lowered the grade and printed false claims.** The skipped
  assessment still counted zero points against a full 25-point maximum, so
  declining to run an analysis dropped the grade a whole band and reported a
  quantum score of 0 for servers that verifiably negotiate a hybrid ML-KEM
  group. A check that did not run now contributes neither points nor maximum,
  and skipped checks are disclosed in `scanWarnings`.
- **ChaCha20 and 3DES cipher suites reported a key size of 0**, which made
  ChaCha20-Poly1305 read as weaker than AES-128 in reports and policy
  evaluation. ChaCha20 now reports 256 bits and 3DES reports its 168-bit key,
  with its 112-bit effective strength and Sweet32 exposure stated in the
  deprecation reason.


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
