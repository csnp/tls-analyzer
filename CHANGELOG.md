# Changelog

All notable changes to QRAMM TLS Analyzer are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-07-30

Reporting release. The verdicts and scores a scan produces are unchanged except
where noted; what changed is that a reader can now reconcile them.

### Fixed

- **The CBOM did not validate against CycloneDX 1.6.** A scan of a host offering
  any non-AEAD cipher suite produced a document declaring `specVersion: 1.6` that
  no 1.6 validator would accept: `primitive: "cipher"` and `mode: "stream"` are
  not members of their closed enums, and one non-member value invalidates the
  whole document. A real scan of example.com produced 19 such errors. This was the
  same defect 0.3.0 fixed for key exchange, where `"kex"` was emitted, one
  function away. A suite with no separate MAC stays `ae`; one that carries a MAC is
  classified by its cipher (`block-cipher` for AES and 3DES, `stream-cipher` for
  ChaCha20 and RC4, `other` for anything unrecognised). The mode now comes from
  the suite name, which carries it, instead of from the encryption summary, which
  is `AES` for every CBC suite and so reported no mode for exactly the suites
  whose mode matters. Verified against the published schema: 0 errors on
  example.com, cloudflare.com and badssl.com.
- **A TLS 1.3-only server was penalised for it.** The protocol dimension added 15
  points for TLS 1.3 and a further 10 for TLS 1.2, so a server offering only TLS
  1.3 could not score above 15 of 25, and turning TLS 1.2 off cost ten points of
  the grade. That is the configuration the `strict` and `cnsa-2.0-2030` policies
  require, so following this tool's own advice lowered its grade. TLS 1.3 now
  carries the dimension on its own, TLS 1.2 alongside it is neither a bonus nor a
  penalty, and only deprecated versions deduct. Measured across all sixteen
  protocol combinations: four change and twelve do not, and all four are
  configurations offering TLS 1.3 without TLS 1.2. Any server that still offers
  TLS 1.2, which is every host checked, reports exactly the same grade as before.
- **The score breakdown could not be added up to the score it sat under.** The
  vulnerability penalty was applied to the grade and never printed, so a
  breakdown reading `Protocol 10 + Cipher 15 + Certificate 25 + Quantum 16 = 66`
  appeared under a headline of `21/100` with nothing to account for the
  difference. The report now prints the dimension subtotal, the penalty itemised
  by severity (`-45  (1 HIGH x 15, 6 MEDIUM x 5)`), and the final score, and the
  arithmetic between them closes. When a dimension was skipped the subtotal also
  shows the raw points, because four dimensions worth 25 each do not total 100
  when one of them did not run. When the penalty exceeds the subtotal the report
  says the score is held at zero rather than leaving the arithmetic open. The
  same three rows are in the HTML report, and `grade.dimensionScore`,
  `grade.vulnerabilityPenalty` and `grade.penalties` are in JSON.
- **One report gave two opposite verdicts for the same standard and the same
  deadline.** `cnsa-2.0-2027: NON-COMPLIANT, 0/100, 16 violations` printed above
  `New NSS Systems (2027-01-01): compliant`. Both were defensible, because they
  measure different things: a policy requires every protocol and cipher suite the
  server still accepts to qualify, while a milestone asks whether the required
  algorithms are available at all. Neither said so. Each verdict now carries a
  scope note that states what it covers and names the other, so a reader who sees
  one can find and interpret the other. Also in JSON as `policyResult.scope` and
  `cnsa2Timeline.scope`.
- **The New NSS Systems milestone reported compliance against a requirement it
  did not check.** Its own requirement list names AES-256, but an absent 256-bit
  suite recorded no gap, so a server whose strongest suite was 128-bit was
  reported compliant. The gap is now recorded, and the milestone reads `partial`
  instead. A scan that enumerated no suites at all still records no gap, because
  missing evidence is not a measured absence. This changes the verdict only for
  servers offering a hybrid post-quantum group and no 256-bit encryption.
- **`--skip-vulns` raised the grade.** Declining to run the vulnerability checks
  removed their penalties, so on cloudflare.com the reported result moved from
  `F (21/100)` to `C (66/100)` purely by looking at less. The penalty cannot be
  known when the check did not run, so the score is now labelled
  `upper bound, vulnerability checks skipped` and the breakdown records the
  penalty as `not measured` rather than as none. `grade.vulnerabilitiesAssessed`
  carries the same distinction in JSON.
- **Batch output was collected in completion order**, so two identical runs
  produced different output and a `--targets` sweep could not be diffed in CI.
  It did not follow the input order at `--concurrency 1` either, because the
  semaphore does not hand out its slot in the order goroutines queued for it.
  Each target now writes to a fixed slot, and a target whose scan fails holds its
  place instead of shuffling the rows around it.
- **An out-of-range or non-numeric port was accepted.** `-p 0`, `-p -5` and
  `-p 70000` all reached the dialer and failed with "no TLS connection could be
  established to example.com:-5 (host unreachable, port closed, or not speaking
  TLS)", which describes the host rather than the rejected argument. Separately,
  a port that was not a number silently fell back to 443, so `example.com:abc`
  reported the target the user typed and scanned a port they never named. Both
  are now refused, and both routes are validated in the one place the flag and
  the target meet.
- **Every error printed the full usage block after the message**, roughly thirty
  lines of stderr for a one-line failure. Runtime errors now print the error
  alone. A mistyped flag points at `--help` rather than listing every flag.
- **The quantum readiness grades and the milestone status glyphs had no key.**
  `Quantum Ready: Q` and a column of `✓ ◐ ○ ✗ —` appeared with nothing to say
  whether either was a good result. Both are now explained in the report, and the
  quantum grades in `--help`.
- **`pkg/types.Duration` marshalled but could not be read back.** It had a
  `MarshalJSON` and no `UnmarshalJSON`, so a consumer importing the public types
  could not decode the tool's own `--format json` output into them.

### Added

- **Releases now publish `checksums.txt`.** Up to 0.3.0 a release carried five
  archives and nothing else, so a downloaded archive could not be checked against
  anything. Download the archives and the file into one directory and run
  `shasum -a 256 -c checksums.txt`.

### Changed

- **The CycloneDX enum check reads the spec instead of a copy of it.** The schema
  test hand-wrote the enum lists and validated a fixture holding one AEAD suite,
  which is the single shape whose primitive was legal, so it passed for three
  releases while the emitted document was invalid. The lists now come from a copy
  of the published schema under `internal/reporter/testdata/cyclonedx/`, guarded
  against being empty, truncated, or containing `"cipher"`, and a new table drives
  every encryption value the scanner can assign with a MAC present and absent.
- **CI fails when a test file is not tracked by git.** The `.gitignore` binary
  patterns were unanchored, so `tlsanalyzer` matched the `cmd/tlsanalyzer`
  directory as well as the built binary and excluded everything in it.
  `cmd/tlsanalyzer/port_test.go`, which holds the regression tests for two of the
  0.3.0 release blockers, was never committed and never ran in CI, while the
  local suite passed throughout because Go does not consult git. The patterns are
  now anchored to the repository root, the two files are committed, and a CI step
  fails on any untracked `_test.go` and prints the rule responsible.

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
