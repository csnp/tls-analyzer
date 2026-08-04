# Changelog

All notable changes to QRAMM TLS Analyzer are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-04

**A minor version rather than a patch, because three things a user can depend on
change.** A policy that is not satisfied now exits 2 where it exited 0, so a CI
job that passed can start failing, which is the point. A policy file with an
unknown key, no name or no rules is refused where it was accepted and reported
compliant. And a certificate that is not valid for the name it was served for,
or that does not chain to a trusted root, scores zero for its dimension where it
scored full marks, which can move the letter grade. A patch number would tell an
operator this upgrade is safe to take unattended, and it is not.

The release began as a reporting release: the score breakdown now reconciles,
the CNSA 2.0 verdicts state their differing scope, and batch output is
deterministic. Repeated review rounds then found a series of fail-open defects in
the analysis itself, and those are what set the version. Each round found the
next one a level below the last fix, several of them inside the previous round's
fix, and the most serious, a chain check that stepped aside for the wrong
certificate, was found in code an earlier round had just tightened and then found
again after its first repair proved inert on macOS and Windows.

### Security

- **The invocation itself could forge the report: a `--targets` file or an
  `--sni` value rewrote the grade a finished scan had printed.** A value carrying
  an ANSI cursor-up sequence reached the terminal unescaped through three print
  sites, so a report that measured `D (41/100)` displayed `A+ (100/100)`. It
  survived `--no-color`, and under `-o` it was worse: this tool strips its own
  colour from a saved report, so the injected sequences were the only escape
  bytes in the file an auditor opens later. The exit code and the JSON stayed
  honest throughout, which is exactly why the text report had to be fixed rather
  than relied on. A targets file is the same "arrives from a vendor, a repository
  or a colleague" shape this release already treats a policy file as.

  The cause was an incomplete list, not a missing call. The sanitiser's own
  documentation named two sources of untrusted text, the policy file and the
  scanned server's certificate, and ten call sites correctly covered those
  two. There is a third, the invocation: the target, which `--targets` may read
  from a file somebody else wrote, and `--sni`. Nothing covered it.

  This is the fourth repair of this defect class in one release and the first
  that does not depend on remembering. The text renderer now scrubs the entire
  result once, on the way in, and the ten per-print-site calls were removed
  rather than kept as a second layer: every print helper in that file is
  unexported and reachable only through the renderer's entry point, so they were
  not an independent defence and no test could tell them from nothing. A print
  site added later is covered without anyone thinking about it. A test fills
  every string the result type carries, found by reflection rather than by a
  list, renders text, JSON, SARIF and CBOM, and fails on any byte that can steer
  a terminal, so a field added to the result type is covered the day it is added.
  JSON, SARIF and CBOM are deliberately left carrying what the server really
  sent, since their encoders escape control characters rather than executing
  them.

  Also closed by the same work: a certificate whose common name was entirely
  control characters was named `""` in the chain-failure reason, because the
  fallback to another identifier tested the raw value for emptiness and scrubbed
  afterwards, so it never fired. It now decides on the value the reader will
  actually see, and falls back through the organization to the serial number,
  which is what the code's own comment always said it did. The cap that stops a
  server pushing this tool's words out of the report is now measured in what `%q`
  renders rather than in bytes: scrubbing removes control characters but leaves
  Unicode format characters, which `%q` expands roughly threefold, and a hostile
  name could still truncate away the sentence saying the platform verifier did
  not identify which certificate it rejected. `U+2028` and `U+2029` are collapsed
  along with the other line terminators.

- **A policy file could forge the tool's own refusal messages, by its contents
  and by its name.** Refusing a policy with an unrecognised key is new in this
  release, and the YAML decoder echoes the offending key's NAME back verbatim
  and untruncated, so a key name carrying a cursor-up sequence and newlines
  printed a fabricated `Status: COMPLIANT  Score: 100/100` on stderr, which
  shares a terminal with the report. The refusals this release added also
  interpolate the policy file's PATH, so a filename could forge the same
  verdict: a repository supplies a file's name as much as its contents, and git
  preserves control bytes in filenames.

  This is the same untrusted source the release already handles elsewhere, the
  policy file, arriving at print sites the release itself introduced. Both are
  closed now, and the sibling sites that print a policy's NAME were left alone
  deliberately, because they use `%q`, which escapes control characters.

  The decoder's message is scrubbed per diagnostic rather than as one string.
  That distinction is the fix's whole point and the first attempt got it wrong:
  yaml reports one entry per problem joined with newlines, those newlines are
  the decoder's rather than the attacker's, and scrubbing the joined text
  collapsed a file with eleven misspelled keys into a single wrapped line with
  five of the eleven dropped behind the length cap. Every misspelled key is
  named, on its own line, with its line number, which is the entire point of
  refusing unknown keys. Untrusted text loses its newlines; tool-authored text
  keeps them.

- **An expired intermediate certificate was reported as a healthy chain.** A
  chain built from a valid trusted root, an expired intermediate and a perfectly
  current leaf was reported as not evaluated rather than failed, took the
  certificate dimension's full 25 of 25 as "Certificate is current", graded
  **A 91/100** with zero findings, and satisfied a policy with exit 0. With
  `--skip-quantum`, where that dimension is excluded and the rest rescaled, the
  same chain graded `A+ 100/100`. An expired intermediate is the most common
  real-world chain failure there is, and no field of the report carried it: every
  other field describes the leaf, and the leaf was healthy.

  The chain check stepped aside whenever Go reported a validity failure, on the
  grounds that the certificate's window "is reported on its own". Go reports that
  for any certificate in the chain, while the expiry flags are derived from the
  leaf alone, so for an expired intermediate nothing reported the window
  anywhere. The check now steps aside only when the LEAF's own window is the one
  that failed. Any other certificate in the chain fails the check, with a reason
  naming that certificate and which end of its window failed, because every other
  field of the report describes the leaf and in this case the leaf is healthy.

  The verdict is decided on the leaf's own window rather than on which
  certificate the verifier blamed, because only one of Go's two verifiers answers
  that question truthfully. Every real scan passes a nil root pool, which on
  macOS and Windows routes to the platform verifier, and those report the leaf as
  the offender whatever actually failed. A first version of this fix compared the
  blamed certificate against the leaf and was therefore inert on exactly the
  platforms most operators run, while the whole suite stayed green, because every
  test passes an explicit pool and that is the only configuration reaching the
  pure-Go verifier. If a window failure is reported and the leaf is inside its
  window, the certificate at fault is by definition not the leaf, whichever
  verifier answered. Where the verifier does not identify it, the scan looks for
  itself: the server presented the rest of the chain on the same connection, so a
  certificate outside its own window is visible from the dates it carries and is
  named. That naming applies wherever the platform reports a validity-window
  failure at all; where it reports only that the chain is untrusted, which macOS
  and Windows may do, the check still fails and the reason is the platform's own,
  which need not name a certificate. The attribution is hedged, because the
  server chose that list and can ship an expired certificate that is not on the
  failing path.
  Where nothing presented is outside its window, the report says the certificate
  at fault came from this machine's trust store rather than from the server.

  The second half of the same defect was that a check which did not run was
  indistinguishable from one that passed. `notPerformed` was neither a violation
  nor a skipped rule in any consumer, so the one mechanism that fails closed
  never fired. Both certificate checks now record a skipped rule when they did
  not run, which marks the verdict incomplete and exits 2, the same path
  `certificate.requireCt` already took.

- **A policy file holding more than one YAML document silently applied only the
  first.** A file whose first document was trivially satisfiable and whose second
  was strict reported the first document's name, `COMPLIANT 100/100` and exit 0,
  while the second document alone failed the same host with seven violations and
  exit 2. The rules the author wrote were discarded without a word and the
  verdict named a policy that was only part of the file. Such a file is refused
  now, naming how many documents were found. A leading or trailing `---` around a
  single document is ordinary YAML and still loads.

- **A policy whose rules could only warn was accepted as a gate.** The guard that
  refuses a policy enforcing nothing asks whether a VALUE can constrain, never
  whether the RULE can produce a violation. Two rules report only into warnings,
  which neither the compliance verdict nor the exit code reads, so
  `quantum.requirePqcCertificates: true` on its own, and
  `certificate.minValidityDays: 3650` on its own, each loaded and then reported
  `COMPLIANT 98/100` with exit 0 forever, in the same report that measured the
  requirement as unmet.

  Both rules warn deliberately and `docs/policies.md` gives the reason for each:
  a certificate inside its renewal window is not misconfigured, and no publicly
  trusted CA issues a post-quantum certificate today, so failing a build on
  either would fail correctly configured hosts for a condition the operator
  cannot remedy. They still warn. What changed is that neither one can any longer
  be the rule that makes a policy look enforceable, so a policy built only from
  them is refused when it loads, naming the rule at fault rather than reporting
  that the policy "defines no rules", which would be false. A policy that also
  contains an enforceable rule is unaffected, and the warnings still appear.

- **A policy file could forge the report it appeared in.** A policy file is
  untrusted input: it arrives from a vendor, a repository or a colleague, and its
  name is rendered into a human-readable verdict. A name containing newlines
  printed its own `Status: COMPLIANT / Score: 100/100` block and pushed the real
  verdict off the screen, and an ANSI escape survived `--no-color`. The exit code
  and the JSON stayed honest throughout, which is why the text report had to be
  fixed rather than relied on. Control characters in the name and description are
  collapsed and the fields are capped, so supplied text can still appear as a
  name but can no longer displace the verdict.

- **A certificate whose validity period had not started was scored as healthy.**
  It took the certificate dimension's full 25 of 25 and graded `A+ 100/100`,
  indistinguishable from a good certificate. Go's verifier reports the same
  reason for both ends of the validity window, and the chain check steps aside
  for that reason because the window is "reported on its own"; the scanner
  derived expiry from `notAfter` alone, so nothing reported the other end. Both
  ends now score zero and raise a CRITICAL finding, and the policy verdict, the
  report status line, the recommendations and the CBOM all say so. A certificate
  with a short future window is no longer also reported as expiring soon, which
  was two findings and two penalties for one condition with the remediation
  pointing the wrong way. Clock skew and pre-staged certificates reach this
  without an adversary.

- **A policy that could not fail was accepted whenever the guard and the
  evaluator read a value differently.** The guard that refuses such a policy
  read the written scalar for itself, first with a hand-rolled number parser and
  then by decoding it into an untyped value, while the evaluator used what YAML
  decodes into the schema field. The readings disagreed in three ways:
  `minKeySize: 0x0` (and octal and binary) was accepted where `minKeySize: 0` was
  refused; `minKeySize: 0.4` was accepted and truncated to 0; and
  `requireForwardSecrecy: no` or `off` was accepted while setting the field to
  false. Each produced `COMPLIANT 100/100` with exit 0 from a policy that
  enforces nothing, and through `extends` that reopened the disarmed-overlay case
  this release closes elsewhere. The guard now reads presence from the document
  and the value from the decoded schema, so one decoder decides what a value
  means. `allowSelfSigned: no` and `off`, which are restrictive, are accepted for
  the same reason.

- **A policy file could burn CPU proportional to the square of its own length.**
  Truncating a long name or rule value rebuilt the whole string after dropping
  each character, so a 300 KB policy name cost about 100 seconds before any
  connection was opened, against 0.03 seconds for a short one. A policy file is
  untrusted input and this tool runs in CI.

### Fixed

- **A scanned server could also forge the findings block.** The
  `CERT_CHAIN_UNTRUSTED` and `CERT_NAME_MISMATCH` descriptions interpolate the
  chain and name reasons, and x509 builds the name reason by joining the
  certificate's own DNS names raw, so an ANSI sequence in a subject alternative
  name reached the finding line unescaped and could overprint it with a passing
  verdict, surviving `--no-color`. The certificate section three blocks above was
  defended first; sanitising one block and not its sibling is not a smaller
  version of that fix, it is the same hole.

- **A scanned server could forge the certificate section of the report.** The
  subject, issuer, SANs and both check reasons are chosen by the server, and the
  text report printed them raw. macOS formats verifier errors as
  `x509: "<subject>" certificate is not trusted`, so a common name carrying an
  ANSI sequence reached the terminal through the chain-trust line and could clear
  and rewrite the line above it, printing a green `Chain trust: OK` over the real
  verdict. It survived `--no-color`, because the escape is in the data rather
  than in the colouring, while the exit code and the JSON stayed honest. This is
  the same forgery the policy-name fix in this release closed, on the path that
  fix did not reach: the sanitiser lived in the analyzer package and nothing in
  the reporter could call it. It now lives in its own package and both use it.

- **The scan coverage notes did not say that revocation is never checked.** That
  section exists to enumerate what the scan does not cover, and it already
  disclosed the protocol probe range, the cipher enumeration limit, whose
  preference the negotiated suite reflects, and the trust store the chain is
  verified against. Leaving revocation out invited a reader to treat the list as
  complete, and revocation is the check most likely to be assumed once a chain
  is reported as trusted. Nothing in the report ever claimed a certificate was
  unrevoked; it now says so out loud, and names a way to check.

- **A policy file whose second document had a syntax error hung the process.**
  The multi-document refusal added in this release walked the rest of the stream
  looking for more documents, and broke out only on end of input. yaml.v3 does
  not advance past a syntax error: it returns the same error on every subsequent
  read, forever. So the walk never terminated, and the tool spun at 100 percent
  of a core before opening any socket, printing nothing at all. In CI that reads
  as a hung scan rather than a rejected file. A document that does not parse is
  now counted, which ends the walk and refuses the file, which was the outcome
  either way.

- **A certificate in its final hours raised no expiring-soon finding at all.**
  The finding was guarded on the remaining-days count being above zero, standing
  in for "the certificate has not expired". That count truncates hours to whole
  days, so a certificate with under 24 hours left counts zero and cleared neither
  that guard nor the expiry finding. The last day of a certificate's life, the
  window where renewal is most urgent, produced silence. The guard asks whether
  the certificate has expired now, which is the question it always meant.

- **A comment claimed a guard was safe in a direction where it was not.** The
  check deciding whether a policy declares any enforceable rule called its own
  fallback arm unreachable, on the strength of a test that inspects yaml tags but
  never the field's kind, so a rule field added as a pointer or a map would have
  reached it with the suite green. The same comment called accepting an unknown
  kind the safe direction, which is backwards: a policy is accepted as soon as
  one rule appears to constrain, so accepting admits a policy that may enforce
  nothing, the exact shape the guard exists to refuse. The arm refuses now, and
  the test asserts the kind against a separately written list so an unhandled
  kind fails the suite when it is added.

- **A text report written with `-o <file>` carried ANSI escape codes.** Colour
  was decided from whether stdout was a terminal, even though the report was
  going to a file, so running the scan from a terminal put 363 escape bytes into
  every saved report. The destination decides now. `--no-color -o <file>` was the
  workaround and is no longer needed.

- **The fix offered for a banned certificate signature could contradict the
  policy that raised it.** The remediation was fixed text reading "reissue with
  SHA-256 or stronger" whatever the policy banned, and the built-in `strict`
  policy bans SHA-256 because it targets SHA-384 or better, so following the
  advice reproduced the violation. The remediation is derived from the policy
  now: it names what the policy requires when it says so, and otherwise names the
  strongest algorithm the policy does not ban. Post-quantum signatures are never
  suggested, because no publicly trusted CA issues one.

- **`requiredVersions` naming SSL 2.0 or SSL 3.0 reported it "not detected".**
  That is as unfounded as reporting it absent, since this scanner cannot offer
  either protocol. It is recorded as not evaluated now, matching
  `bannedVersions`. This is deliberately NOT extended to `minVersion`: every
  policy sets a minimum, so recording the unmeasurable region below TLS 1.0 as a
  skipped rule would mark every evaluation incomplete forever and make that
  signal meaningless. The protocol probe range is disclosed in the scan coverage
  notes instead.
- **Policy rule VALUES were never validated, so a typo turned a rule off and the
  report read compliant.** The strict validation added in this release covers
  keys only. `bannedVersions: ["TLSv1.2"]` matched no scanned protocol, so the
  rule left the verdict and the report read `COMPLIANT 100/100` with exit 0
  against a server that does enable TLS 1.2; `tls 1.2`, `TLS1.2`, a trailing
  space and `nonsense` behaved the same way. `minVersion` was worse than silent,
  because an unrecognised key in a Go map reads back as 0, which is the rank of
  SSL 3.0, so `minVersion: garbage` was satisfied by any protocol at all. An
  unrecognised protocol version is now refused when the policy loads, naming the
  value and listing the accepted spellings. Algorithm, cipher suite and signature
  names are a free-form space rather than a closed set, so those are matched
  without regard to case instead: `sha1` banned nothing while `SHA1` banned two
  suites on the same host, with nothing in the output saying which had happened.
- **`minVersion` checked what the server could reach, not what it still
  accepted.** `minVersion: TLS 1.3` reported `COMPLIANT 100/100` with exit 0
  against a server that also accepted TLS 1.0, in the same report that listed
  TLS 1.0 as supported and raised a HIGH finding for it. The rule's name, the
  Scope paragraph printed beside the verdict, and every server configuration
  directive of the same name all mean a floor on what is accepted, so that is
  what it checks now; the capability half still fires separately when a server
  cannot reach the minimum at all. `cnsa-2.0-2027` and `cnsa-2.0-2035` set a
  minVersion and no `bannedVersions`, so both gave a clean protocol verdict to a
  TLS 1.0 server: on example.com they now report 2 and 3 protocol violations
  where they reported none.
- **A certificate no client would accept could satisfy a certificate policy.**
  A policy asking for key size, lifetime and a CA-issued certificate reported
  `COMPLIANT 100/100` against `wrong.host.badssl.com` and
  `untrusted-root.badssl.com`, in the same report that printed
  `NOT VALID FOR THIS NAME` and scored the certificate dimension 0 of 25. Every
  individual rule really was satisfied, so the name and chain results are now
  read by the policy evaluator as well as by the grade. A check that did not run
  is still not read as a failure.
- **A protocol version the policy said MUST be supported produced only a
  warning.** `requiredVersions: ["TLS 1.3"]` against a server without TLS 1.3
  reported `COMPLIANT` and exit 0, while the same report printed
  `TLS 1.3  Not Supported` and `Fix: Enable TLS 1.3`. Two built-in CNSA 2.0
  policies require TLS 1.3, so a CI gate on either was green whatever the server
  did. It is a violation now. `certificate.minValidityDays` and
  `quantum.requirePqcCertificates` remain warnings, which is deliberate in both
  cases and is now stated in `docs/policies.md` rather than left to be
  discovered: the first is a renewal threshold rather than a compliance failure,
  and no publicly trusted CA issues a post-quantum certificate yet.
- **Algorithm names were matched literally, so the separators decided whether a
  rule applied.** Banning `SHA-256`, which is the spelling NIST uses and the one
  this tool's own remediation text teaches, silently did nothing against a
  certificate whose signature field reads `SHA256-RSA`, and reported
  `COMPLIANT 100/100`. Algorithm, cipher suite and signature names are now
  compared on their letters and digits alone, so `SHA-256`, `SHA256`, `sha_256`
  and `Sha 256` all name the same thing.
- **Three ways to write a policy that constrains nothing, and one restrictive
  rule that was refused.** A rules block whose only key was `cnsa2TargetYear`, a
  rule set to an empty list, and a list whose only item was blank each loaded and
  reported `COMPLIANT 100/100` against a host that satisfied nothing, which is
  exactly what the "defines no rules" guard exists to prevent. The same guard
  refused `allowSelfSigned: false`, the restrictive setting every built-in policy
  uses, because Go cannot tell an unset field from one set to its zero value.
  Whether the document declares a rule is now read from the YAML instead.
- **Six rule fields were declared, documented, printed by `print-policy`, and
  never read.** `protocol.maxVersion`, `certificate.maxValidityDays`,
  `certificate.requiredSignatureAlgorithms`, `cipher.allowedCipherSuites` and
  `quantum.requiredKeyExchangeAlgorithms` produced no violation, no warning and
  no "not evaluated" entry, which reads as a pass. Requiring ML-DSA-65 of a
  SHA256-RSA certificate, or ML-KEM-768 of a host with no post-quantum key
  exchange at all, reported `COMPLIANT 100/100` and exit 0. The last two are
  named by all three built-in CNSA 2.0 policies, where the gap was masked by
  `cipher.requiredKeyExchange` covering the same ground, so a user who kept only
  the quantum block of a printed policy got an unconditional pass on this tool's
  flagship post-quantum use case. All five are evaluated now.
  `certificate.requireCt` is the sixth: this scanner collects no signed
  certificate timestamps and queries no Certificate Transparency log, so it is
  recorded as not evaluated with a reason, which marks the verdict incomplete
  rather than reporting a requirement met by a scanner that never looked.
- **Banning SSL 2.0 or SSL 3.0 passed without being tested.** Go's TLS stack will
  not offer either protocol, so the scanner never reports one and the ban could
  not fire. `modern`, `strict` and `cnsa-2.0-2030` all banned SSL 3.0, so that
  rule had passed on every host ever scanned without once being checked. The
  built-in policies no longer declare it, because a policy shipped with the tool
  should only state what the tool can check. Both names are still accepted in a
  policy file you write, and each records the rule as not evaluated, marking the
  verdict incomplete and exiting 2, the same way `certificate.requireCt` does.
  The reason points at a scanner with legacy protocol support rather than at
  `openssl s_client -ssl3`, which OpenSSL 3.x no longer accepts.
- **The certificate name and chain were asserted, not verified.** The scanner
  handshakes with verification disabled on purpose, so it can connect to and
  describe a certificate a verifying client would refuse. Nothing replaced the
  two checks that disabling verification skipped, so both of these were reported
  as perfect: `tlsanalyzer wrong.host.badssl.com` gave `Certificate 25/25` and
  `Status: Valid` for a certificate whose only names are `*.badssl.com` and
  `badssl.com`, and `tlsanalyzer untrusted-root.badssl.com` gave
  `Certificate 25/25` and "Valid certificate from trusted CA" for a chain built
  on a root nothing trusts. openssl answers `verify error:num=62:hostname
  mismatch` and `verify error:num=19` for the same two hosts. Reproducible
  without badssl as `tlsanalyzer example.com --sni cloudflare.com`. Both checks
  now run as separate questions with separate answers, and each is printed
  whatever its outcome including when it did not run. Either failing scores the
  certificate dimension zero, as expiry already did. The authoritative name is
  the one sent in the ClientHello, which is the `--sni` value when given and the
  target otherwise; when the two differ a scan warning names both. Chain trust is
  decided against the trust store of the machine running the scan, which a scan
  warning also states. Measured on five well-configured public hosts: grade and
  certificate score unchanged, both checks passing.
- **An empty or unparseable `--policy-file` reported `COMPLIANT 100/100`.** An
  empty file produced `{"policyName": "", "compliant": true, "score": 100}` and
  exit 0 on a host that `--policy strict` failed with 35 HIGH violations at the
  same moment, and a file whose keys were all misspelled did the same, because
  unknown keys were ignored. Refused now, each with a reason and a next step: no
  YAML document, no `name`, no rules after inheritance, an unknown key, or an
  `extends` naming a policy that does not exist. Parse errors name the YAML path
  rather than the Go type, so the tool's own diagnostics are no longer where the
  schema leaks.
- **`extends` silently discarded most of the policy file.** The merge copied a
  hand-picked eight rule fields; measured against the current schema it dropped
  13 of 16 overridden fields plus the whole `weights` block, so a file extending
  `modern` to ban AES, require an 8192-bit RSA key or forbid a signature
  algorithm was accepted, reported under its own name, and evaluated against the
  base policy's looser rules. The overlay is applied by decoding the document
  onto a copy of the base now, so it cannot drift as rule fields are added. The
  inheritance example in `docs/policies.md` was one of the cases that did not
  work.
- **`docs/policies.md` documented four keys that do not exist.**
  `cipher.preferredCipherSuites`, `quantum.requireFullPqc`,
  `quantum.requiredSignatureAlgorithms` and `certificate.requireCT` (the tag is
  `requireCt`) were all silently ignored, so a policy written from the complete
  example in that document applied fewer rules than it appeared to. Now that
  unknown keys are refused, such a policy would be rejected outright, so the
  document is corrected and two tests keep it honest: every YAML block in it is
  put through the real loader, and every key in the schema has to appear in it.
  Five keys the schema defines were also missing from the document.
- **A policy rule whose input was never measured was failed as if it were zero.**
  `tlsanalyzer google.com --skip-quantum --policy cnsa-2.0-2035` printed
  `Quantum Ready: not assessed` and `[HIGH] Quantum readiness score below
  minimum, Expected: >= 90 | Actual: 0` in the same report, against a host whose
  full scan reports 64. The assessment now records whether it ran; the rule is
  skipped and named, with its reason, and the whole verdict is marked
  incomplete. That matters because the policy score deducts from 100, so a rule
  that is not evaluated can only raise it: measured on the same host and policy,
  the skipped run scores higher, and both the status and the score now say the
  number is not comparable.
- **Three more consumers read the same unmeasured value as a measurement.**
  Sweeping every reader of the quantum score found the SARIF reporter publishing
  a `QUANTUM_VULNERABLE` finding with an empty message into the format CI systems
  act on, and the HTML report drawing a Quantum Risk Assessment section with an
  empty risk level badge styled as low risk and a score of 0 out of 100. Both are
  guarded, and `riskClass` no longer returns the reassuring class for a level it
  does not recognise. A cross-surface test now asserts over text, JSON, SARIF and
  HTML at once.
- **`--policy` non-compliance exited 0, so no CI gate was possible.** The tool
  could report 35 HIGH violations and let a pipeline through, and the exit codes
  were documented nowhere. A policy that is not satisfied, or that could not be
  fully evaluated, exits 2 now; a scan that could not complete exits 1; both are
  documented in `--help`, the README and `docs/policies.md`. A scan failure
  outranks the policy gate, because a target that was never reached carries no
  verdict.
- **A batch sweep in `--format json` exited 0 with an unreachable target**, while
  the same sweep in text format exited 1. Released 0.3.0 exits 0 in both formats,
  so this release's own batch fix had landed on one of the two output paths.
- **The HTML report painted supported TLS 1.0 and TLS 1.1 rows with the same
  green check as TLS 1.3**, while the text report marked them "Supported
  (Deprecated)" and the vulnerability list flagged TLS 1.0 HIGH. The
  `.status-warn` class was defined in the stylesheet and used nowhere, so the
  warning styling was intended and lost. The icon and the badge now read one
  shared predicate, asserted against both reports.
- **The text report discarded the per-violation remediation that JSON carried**,
  so the default output named every problem and no fix.
- **`--policy` and `--policy-file` both named a policy and only one was applied**,
  with nothing saying which. Passing both is an error.

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
- **`--skip-quantum` raised the grade, on a post-quantum readiness tool.**
  Excluding a skipped dimension keeps the score honest about what it measured, but
  it also renormalises over the dimensions that remain, and quantum readiness is
  the one most servers score worst on. So declining the assessment moved
  github.com from `D (40/100)` to `C (61/100)`, and a well-configured host reached
  `A+ (100/100)` by not looking. The raise is inherent to excluding a dimension and
  is unchanged; what is new is that the score now says it is not comparable with a
  full scan's and names the dimension that did not run, both on the headline and in
  the breakdown. `grade.skippedDimensions` carries the same in JSON.
- **A `--targets` sweep graded hosts it never reached, and exited 0.** Every
  unreachable host rendered as a finished assessment: `TLS Security: (0/100)` with
  a blank letter, a quantum score of 0 and an unticked hybrid PQC line, for a host
  that did not resolve. The reason was on the result and in `--format json` all
  along; the text renderer, the default format, discarded it. A sweep during a DNS
  blip therefore produced a confident failing row per host and a success exit, so
  `tlsanalyzer --targets hosts.txt && deploy` proceeded on a scan that measured
  nothing. The same defect 0.3.0 fixed for the single-target path, surviving in
  batch because the error travels on the result rather than as a returned error. An
  unscanned target now renders a `NOT SCANNED` block with the reason and no grade,
  and batch exits non-zero naming every target that failed.
- **`--concurrency` and `--timeout` accepted values the tool could not act on.**
  `--concurrency 0` hung forever on an unbuffered semaphore with nothing on either
  stream, `--concurrency -1` panicked out of `make()` with a stack trace that also
  printed absolute source paths, and `--timeout 0` or a negative value meant no
  timeout at all, so one unresponsive host wedged a whole sweep. `--port` was the
  only numeric flag that was checked; all three are now refused by name. Flag
  validation also moved ahead of target collection, so
  `tlsanalyzer --concurrency 0` no longer answers that it has no targets while
  saying nothing about the value it cannot use.
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

- **`tlsanalyzer print-policy <name>`** prints a built-in policy in exactly the
  shape `--policy-file` accepts. That matters more now that unknown keys are
  refused: a user needs a correct starting point, not just a stricter parser. All
  five built-in policies round-trip through it back into the loader.
- **Releases now publish `checksums.txt`.** Up to 0.3.0 a release carried five
  archives and nothing else, so a downloaded archive could not be checked against
  anything. Download the archives and the file into one directory and run
  `shasum -a 256 -c --ignore-missing checksums.txt`. The flag is required:
  without it the archives you did not download are reported as failures and the
  command exits 1.

### Changed

- **The suite reported for TLS 1.3 is marked as the one this scan negotiated.**
  Go offers all three TLS 1.3 suites and ignores per-suite configuration, so the
  suite reported is chosen by this scanner's client preference and not the
  server's. Measured against openssl 3.6.1: example.com, cloudflare.com and
  google.com each negotiate `TLS_AES_256_GCM_SHA384` with a client that offers
  AES-256 first, while this scanner reports `TLS_AES_128_GCM_SHA256` for all
  three. The verdict is unchanged, since a server that accepts a 128-bit suite is
  reported as accepting one; what changes is that the evidence no longer claims
  to be the server's preference.
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

[0.4.0]: https://github.com/csnp/tls-analyzer/releases/tag/v0.4.0
[0.3.0]: https://github.com/csnp/tls-analyzer/releases/tag/v0.3.0
