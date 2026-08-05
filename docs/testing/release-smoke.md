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
- [ ] `TLS_AES_128_GCM_SHA256` reports `bits: 128`, not 256, and is marked
      `negotiated: true`. It is the suite this scanner's client preference
      selects, not the server's: openssl offering AES-256 first negotiates
      `TLS_AES_256_GCM_SHA384` with the same host. A scan warning has to say so.

### 5a. The two checks a disabled handshake verification would skip

The scanner handshakes with verification off on purpose. Both checks it would
otherwise skip have to run, and each must be reported whatever its outcome.

- [ ] `tlsanalyzer wrong.host.badssl.com` reports the name check as failed, the
      certificate dimension as `0/25`, and a `CERT_NAME_MISMATCH` HIGH finding.
      Ground truth: `echo | openssl s_client -connect wrong.host.badssl.com:443
      -servername wrong.host.badssl.com -verify_hostname wrong.host.badssl.com`
      reports `verify error:num=62:hostname mismatch`. Note the flag:
      `s_client` does not verify the hostname without it and reports
      `Verification: OK`, which looks exactly like the tool being right.
- [ ] Positive control on the same certificate:
      `-verify_hostname badssl.com` reports `Verification: OK`.
- [ ] `tlsanalyzer untrusted-root.badssl.com` reports the chain as not trusted,
      the certificate dimension as `0/25`, and a `CERT_CHAIN_UNTRUSTED` HIGH
      finding. openssl reports `verify error:num=19`.
- [ ] `tlsanalyzer example.com --sni cloudflare.com` reports the certificate as
      valid for `cloudflare.com`, and a scan warning names both that name and
      the target, because "Target: example.com" and "valid for cloudflare.com"
      are not the same claim.
- [ ] Acceptance control: a well-configured public host (example.com,
      cloudflare.com, github.com) reports both checks passing and the same
      certificate score as the previous release. A guard that refuses real input
      is a false clean of the opposite kind.

## 6. Determinism

- [ ] Run the same scan five times. The `protocols` array order and the
      `preferred` marker are identical every run. Concurrency previously made
      both vary between runs.
- [ ] Batch output follows the targets file, not completion order. With a file of
      at least four hosts of visibly different latency, run
      `tlsanalyzer --targets hosts.txt --format json | jq -r '.[].target'` three
      times at the default concurrency and once at `--concurrency 1`. All four
      runs list the hosts in file order. Before 0.4.0 the order varied between
      identical runs, including at `--concurrency 1`.

## 6a. The numbers reconcile

Every number a reader can add up has to add up, and a number that was not
measured must not read as a measurement.

- [ ] The score breakdown closes: the dimension lines total the printed
      `Dimension subtotal`, and `subtotal - Vulnerability penalty` equals the
      printed `TLS Security score` and the headline. Use a host with findings, for
      example `tlsanalyzer example.com`, where 66 - 45 = 21.
- [ ] The penalty line itemises the severities behind it, and the counts match the
      VULNERABILITIES section.
- [ ] `--skip-vulns` prints `upper bound, vulnerability checks skipped` beside the
      grade and `not measured` on the penalty line. Declining a check must never
      read as a better result: it previously moved example.com from F (21/100) to
      C (66/100) with no qualifier.
- [ ] `--skip-quantum` normalises the subtotal over the three dimensions that ran
      and says one dimension was not assessed.
- [ ] `--policy cnsa-2.0-2027` on a host with hybrid key exchange and weaker
      suites still on offer: the policy verdict and the CNSA 2.0 timeline
      milestone for the same year may differ, and BOTH print a `Scope:` note that
      says what they cover and names the other. Two opposite verdicts for one
      deadline with no scope stated is the defect this closes.
- [ ] The report keys its own markers: the milestone list carries a glyph legend
      and the grade block explains Q+, Q, Q- and QV.

## 6b. Published artifact

Verify the artifact users download, not a local build. CI injects the version, so
a local build cannot prove the release does.

- [ ] The release carries `checksums.txt` plus all five archives.
- [ ] Download one archive and the checksums file into an empty directory, then
      `shasum -a 256 -c --ignore-missing checksums.txt` reports OK.
      `--ignore-missing` is required, since the file lists all five.
- [ ] The extracted binary's `version` reports the tag being released, and the
      commit matches the tagged commit.
- [ ] Re-run one behaviour that changed in this release on the downloaded binary.

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
- [ ] `tlsanalyzer print-policy <name>` for every listed policy produces YAML
      that `--policy-file` then accepts. A starting point the parser rejects is
      worse than none.
- [ ] Every YAML key in `docs/policies.md` is a key the loader accepts, and every
      key in the schema appears in that document. Both directions are enforced by
      tests; check one by hand, because the document is the only description of
      the schema now that unknown keys are refused.
- [ ] A policy file that cannot be understood is refused rather than reported
      compliant: an empty file, a file with no `name`, a file with no rules, a
      file with a misspelled key, and an `extends` naming a policy that does not
      exist. Each names the problem and a next step. Before 0.4.0 an empty file
      reported `COMPLIANT 100/100` and exit 0.
- [ ] `--policy` and `--policy-file` together is an error, not a silent win for
      one of them.

### 8b. Rule VALUES, not just rule keys

Refusing unknown keys says nothing about the values under them. Both gate runs
that found a fail-open policy defect found it one level deeper than the last fix
reached, so check the level below whatever was last tightened.

- [ ] A misspelled protocol version is refused when the policy loads, not
      silently dropped. Try `bannedVersions: ["TLSv1.2"]`, `["tls 1.2"]`,
      `["TLS1.2"]`, a trailing space, and `minVersion: garbage`, against a host
      that does enable TLS 1.2. Each must exit 1 naming the value and listing the
      accepted spellings. Before this check existed every one of them reported
      `COMPLIANT 100/100` and exit 0.
- [ ] Acceptance control: `bannedVersions: ["TLS 1.2"]` against the same host is
      a violation and exits 2, and `["SSL 2.0"]` still loads.
- [ ] Banning `SSL 3.0` in a HAND-WRITTEN policy prints
      a warning that the rule could not be tested and names another way to check
      it. Go cannot offer SSL 2.0 or SSL 3.0, so silence there is not compliance.
- [ ] Algorithm names match case-insensitively: `bannedAlgorithms: [sha1]` and
      `[SHA1]` produce the same verdict on the same host.
- [ ] **Every rule field in the schema changes a verdict in at least one
      direction.** Read the field list from the struct tags in
      `pkg/types/policy.go`, and for each one construct a policy that the target
      does not satisfy. A field with no evaluator produces no violation, no
      warning and no "not evaluated" entry, which reads as a pass: six of them
      shipped that way, including two named by the built-in CNSA 2.0 policies
      where `cipher.requiredKeyExchange` masked the gap by covering the same
      ground. `grep -rn '\.FieldName' internal/ --include='*.go'` with no hit
      outside the type definition is the cheap version of this check.
- [ ] `certificate.requireCt` is reported as not evaluated, since the scanner
      collects no SCTs, and the verdict is marked incomplete and exits 2.

### 8a. Exit codes

- [ ] `tlsanalyzer example.com --policy strict; echo $?` prints 2. A compliance
      check that cannot fail a build is not a gate, and this exited 0 before
      0.4.0.
- [ ] A host that satisfies the policy exits 0, so the gate is not simply always
      failing.
- [ ] `--skip-quantum` against a policy with a `minQuantumScore` exits 2 and the
      report lists the rule under "Not evaluated" with its reason. A verdict that
      skipped rules has not established compliance, and the policy score only
      rises when a rule is not evaluated.
- [ ] An unreachable host exits 1, not 2, with or without `--policy`. A target
      that was never reached carries no verdict.
- [ ] A `--targets` sweep containing an unreachable host exits non-zero in
      **both** `--format text` and `--format json`. Before 0.4.0 the JSON path
      exited 0, so the fix had landed on one of the two output paths.
- [ ] Bad input fails cleanly: unreachable host, invalid port, unknown policy,
      unknown format. No panics and no stack traces.
- [ ] An error prints the message alone, not the usage block after it. Check
      `--format bogus`, an unreachable host, and `-p 0`: each is one line on
      stderr. A mistyped flag adds a pointer to `--help`.
- [ ] Port range is enforced on both routes. `-p 0`, `-p -5` and `-p 70000` are
      refused naming the flag; `host:70000` and `host:abc` are refused naming the
      value; `-p 1`, `-p 65535` and `host:8443` are accepted. An out-of-range port
      previously reached the dialer and was reported as an unreachable host.

## 9. Test integrity

- [ ] `git ls-files --others -- '*_test.go'` prints nothing. A test file git does
      not track is a test CI never runs, while the local suite still passes
      because Go does not consult git. An unanchored `tlsanalyzer` pattern in
      `.gitignore` hid the whole `cmd/tlsanalyzer` test file for a full release.
      CI enforces this too; check it here so a local run cannot look greener than
      the pipeline.

## Result

- Date:
- Tester:
- Verdict: PASS / FAIL
- Notes:
