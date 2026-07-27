# Release smoke test: qramm-tls-analyzer

Manual pre-release walkthrough. Run this before every tag push. Record the
actual output, not a summary. Automated tests are necessary but not sufficient:
this tool's verdicts are only useful if they match an independent source, so
every quantum claim below is cross-checked against OpenSSL.

Requires Go 1.25 or later and an OpenSSL with TLS 1.3 hybrid group support
(OpenSSL 3.5 or later prints `Negotiated TLS1.3 group`).

## 1. Build clean

- [ ] `go build ./...` succeeds with no output.
- [ ] `go vet ./...` is clean.
- [ ] `go test ./...` passes.
- [ ] `go test -race ./...` passes. The scanner runs concurrent probes, and an
      earlier release shipped an ordering bug this catches.

## 2. Version provenance

- [ ] `tlsanalyzer version` prints the version being released, not a stale
      constant. Release builds inject it with `-X main.version`.
- [ ] `tlsanalyzer example.com --format json | jq .scannerVersion` matches.
      Reports previously recorded `0.1.0` regardless of the installed release.

## 3. Post-quantum detection, cross-checked

The check that matters most. The tool exists to report post-quantum readiness,
and before 0.3.0 it reported every connection as quantum vulnerable.

- [ ] Ground truth first:
      `echo | openssl s_client -tls1_3 -connect pq.cloudflareresearch.com:443
      -servername pq.cloudflareresearch.com 2>/dev/null | grep "TLS1.3 group"`
      Expect `Negotiated TLS1.3 group: X25519MLKEM768`.
- [ ] `tlsanalyzer pq.cloudflareresearch.com --format json | jq '.keyExchanges'`
      reports `X25519MLKEM768`, `type: hybrid`, `quantumSafe: true`,
      `negotiated: true`, `pqcAlgorithm: ML-KEM-768`.
- [ ] The scan lists additional groups the server supports beyond the negotiated
      one, each marked `negotiated: false`.
- [ ] A host with no hybrid support reports only classical groups and
      `quantumSafe: false`. Confirm the host with OpenSSL first, since public
      hosts enable hybrid groups over time and any given example will change.

## 4. Verdict sanity

A score that does not match intuition is a broken score, not a finding.

- [ ] A server running hybrid key exchange is NOT graded HIGH or CRITICAL and is
      NOT advised to begin hybrid PQC implementation. It already did.
- [ ] A classical-only server IS graded CRITICAL with immediate action.
- [ ] `timeToAction` never recommends work the operator cannot perform.
      Post-quantum certificates are unavailable from publicly trusted CAs, so
      advice must be to track CA readiness, not to deploy ML-DSA today.

## 5. Certificate facts, cross-checked

- [ ] Fingerprint matches OpenSSL exactly:
      `echo | openssl s_client -connect example.com:443 -servername example.com
      2>/dev/null | openssl x509 -outform der | shasum -a 256`
      compared against `jq -r .certificate.fingerprints.sha256`.
      These were previously certificate prefixes, not digests.
- [ ] `publicKeyBits` is non-zero and matches
      `openssl x509 -noout -text | grep "Public-Key"` for both an EC and an RSA
      certificate. EC certificates previously reported 0.
- [ ] `TLS_AES_128_GCM_SHA256` reports `bits: 128`, not 256.

## 6. Determinism

- [ ] Run the same scan five times. The `protocols` array order and the
      `preferred` marker are identical every run. Concurrency previously made
      both vary between runs.

## 7. Output formats

- [ ] `--format text` renders without broken alignment.
- [ ] `--format json` is valid JSON (`| jq .` succeeds).
- [ ] `--format sarif` is valid JSON and carries the release version.
- [ ] `--format cbom` is valid JSON and validates against the CycloneDX 1.6
      schema. The sibling tool csnp/cryptoscan shipped an invalid CBOM for 84
      days, so validate rather than eyeball this one.
- [ ] `--format html -o report.html` opens in a browser and renders.

## 8. Command surface

- [ ] `tlsanalyzer --help` lists every flag used above, and every flag mentioned
      in help text or the README is actually registered.
- [ ] `tlsanalyzer policies` lists policies, and each name is accepted by
      `--policy`.
- [ ] Bad input fails cleanly: unreachable host, invalid port, unknown policy,
      unknown format. No panics and no stack traces.

## Result

- Date:
- Tester:
- Verdict: PASS / FAIL
- Notes:
