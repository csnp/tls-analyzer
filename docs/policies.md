# Policy-Based Scanning Guide

QRAMM TLS Analyzer supports policy-as-code for automated compliance checking. This guide explains how to use built-in policies and create custom ones.

## Built-in Policies

### List Available Policies

```bash
tlsanalyzer policies
```

Output:
```
Available Security Policies:
─────────────────────────────────────────────────────────

  modern
    Modern TLS configuration for 2024+

  strict
    Strict TLS configuration with TLS 1.3 required

  cnsa-2.0-2027
    CNSA 2.0 compliance target for 2027 - new NSS systems

  cnsa-2.0-2030
    CNSA 2.0 compliance target for 2030 - TLS 1.3 required

  cnsa-2.0-2035
    CNSA 2.0 compliance target for 2035 - full PQC
```

### Policy Descriptions

| Policy | Use Case |
|--------|----------|
| `modern` | General-purpose secure configuration for web applications |
| `strict` | High-security environments requiring TLS 1.3 only |
| `cnsa-2.0-2027` | Government/defense systems needing CNSA 2.0 by 2027 |
| `cnsa-2.0-2030` | Systems targeting 2030 compliance deadline |
| `cnsa-2.0-2035` | Full post-quantum transition planning |

## Using Built-in Policies

```bash
# Evaluate against a policy
tlsanalyzer example.com --policy modern

# Multiple formats
tlsanalyzer example.com --policy cnsa-2.0-2027 --format json
tlsanalyzer example.com --policy strict --format html -o report.html
```

## Custom Policies

Create custom policies in YAML format to match your organization's requirements.

### Basic Structure

```yaml
name: my-organization-policy
version: "1.0"
description: Custom security policy for my organization
extends: modern  # Optional: inherit from built-in policy

rules:
  protocol:
    # Protocol version requirements
  cipher:
    # Cipher suite requirements
  certificate:
    # Certificate requirements
  quantum:
    # Quantum readiness requirements
```

### Protocol Rules

```yaml
rules:
  protocol:
    # Minimum acceptable TLS version. This is a floor on what the server
    # ACCEPTS, not just on what it can reach: a server that negotiates TLS 1.3
    # but still accepts TLS 1.0 violates a minVersion of TLS 1.2. Both halves are
    # checked, so a server that cannot reach the minimum at all is also a
    # violation.
    minVersion: TLS 1.2

    # Versions that MUST be supported. A version listed here and not offered by
    # the server is a violation, so this can fail a build.
    requiredVersions:
      - TLS 1.3

    # Versions that MUST NOT be supported
    bannedVersions:
      - TLS 1.0
      - TLS 1.1

    # Highest acceptable TLS version
    maxVersion: TLS 1.3
```

Protocol versions are written exactly as `SSL 2.0`, `SSL 3.0`, `TLS 1.0`,
`TLS 1.1`, `TLS 1.2` or `TLS 1.3`. Any other spelling is refused when the policy
loads, naming the value and listing the accepted ones. `TLSv1.2`, `TLS1.2` and
`tls 1.2` are all rejected rather than quietly matching nothing: an unrecognised
version used to leave the rule out of the verdict entirely, so a policy banning
`TLSv1.2` reported COMPLIANT against a server that does enable TLS 1.2.

`SSL 2.0` and `SSL 3.0` may be named, because banning them is a reasonable thing
to require, but this scanner cannot test them. Go's TLS stack will not offer
either protocol, so the scanner never sees one and the absence of a result is not
evidence the server has it disabled. Banning either records the rule as not
evaluated, which marks the whole verdict incomplete and exits 2, the same way
`certificate.requireCt` does. Confirm it with a scanner built with legacy
protocol support, such as nmap's `ssl-enum-ciphers` script; OpenSSL 3.x removed
the `-ssl2` and `-ssl3` client options, so `s_client` cannot answer this either.

A `requiredVersions` entry naming one is recorded the same way. A `minVersion`
is not: every policy sets one, so marking them all incomplete would make the
signal meaningless, and the scan coverage notes disclose the probe range instead.

No built-in policy bans them, for that reason. Until this release `modern`,
`strict` and `cnsa-2.0-2030` all banned SSL 3.0, and that rule had passed on
every host ever scanned without once being tested.

### Cipher Rules

```yaml
rules:
  cipher:
    # Minimum symmetric key size in bits
    minKeySize: 128

    # Require forward secrecy (ephemeral key exchange)
    requireForwardSecrecy: true

    # Algorithms that MUST NOT be used
    bannedAlgorithms:
      - 3DES
      - RC4
      - MD5
      - SHA1
      - DES
      - EXPORT

    # Specific cipher suites to ban
    bannedCipherSuites:
      - TLS_RSA_WITH_AES_128_CBC_SHA
      - TLS_RSA_WITH_AES_256_CBC_SHA

    # Only these cipher suites are acceptable. Leave unset to allow any suite
    # that satisfies the other rules.
    allowedCipherSuites:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256

    # At least one of these key exchange algorithms must be available
    requiredKeyExchange:
      - X25519MLKEM768
      - SecP384r1MLKEM1024
```

Algorithm, cipher suite and signature names are matched on their letters and
digits alone, so case and separators do not decide whether a rule applies:
`SHA-256`, `SHA256`, `sha_256` and `Sha 256` all name the same thing. That
matters because the spellings disagree between sources. NIST writes `SHA-256`,
this tool's own remediation text writes `SHA-256`, and the certificate field
reads `SHA256-RSA`; matching them literally meant banning `SHA-256` silently did
nothing and reported compliant against a certificate signed with exactly that.

Unlike protocol versions these are not a closed set, so an unrecognised name
cannot be refused when the policy loads: banning an algorithm no suite on the
server uses is a legitimate rule that simply does not fire.

### Certificate Rules

```yaml
rules:
  certificate:
    # Minimum days until expiry. This one is a warning threshold: a certificate
    # below it is reported as expiring soon but does NOT fail the policy, so do
    # not use it as a CI gate on renewal. An already expired certificate is a
    # violation. Because it cannot fail a policy, it cannot be the only rule a
    # policy defines; see "Rules that only warn" below.
    minValidityDays: 30

    # Maximum certificate lifetime in days
    maxValidityDays: 397

    # Minimum RSA key size in bits
    minRsaKeySize: 2048

    # Minimum ECC key size in bits
    minEccKeySize: 256

    # Signature algorithms the certificate must use one of
    requiredSignatureAlgorithms:
      - ECDSA-SHA384

    # Signature algorithms to ban
    bannedSignatureAlgorithms:
      - SHA1
      - MD5
      - MD2

    # Allow self-signed certificates
    allowSelfSigned: false

    # Require certificate transparency. This scanner collects no signed
    # certificate timestamps and queries no CT log, so it has no evidence either
    # way: setting this records the rule as not evaluated and marks the whole
    # verdict incomplete, which exits 2. Check the certificate at https://crt.sh
    # to evaluate the requirement yourself.
    requireCt: true
```

### Quantum Rules

```yaml
rules:
  quantum:
    # Require hybrid PQC key exchange
    requireHybridKeyExchange: true

    # Require a post-quantum certificate signature. No publicly trusted CA
    # issues one yet, so this raises a warning rather than a violation. Because
    # it cannot fail a policy, it cannot be the only rule a policy defines; see
    # "Rules that only warn" below.
    requirePqcCertificates: false

    # Minimum quantum readiness score (0-100)
    minQuantumScore: 50

    # Which CNSA 2.0 deadline this policy is written against. This is a label,
    # not a constraint: it is shown beside the policy in `tlsanalyzer policies`
    # and enforces nothing on its own. The rules above it are what the target
    # year means in practice.
    cnsa2TargetYear: 2027

    # Required key exchange algorithms
    requiredKeyExchangeAlgorithms:
      - ML-KEM-768
      - ML-KEM-1024
      - X25519MLKEM768
```

Certificate signature requirements live under `rules.certificate`, not here.

### Scoring weights

```yaml
weights:
  protocol: 25
  cipher: 25
  certificate: 25
  quantum: 25
```

## Complete Example

```yaml
# financial-services-policy.yaml
name: financial-services-policy
version: "2.0"
description: Secure TLS policy for financial services with PQC readiness

rules:
  protocol:
    minVersion: TLS 1.2
    requiredVersions:
      - TLS 1.3
    bannedVersions:
      - TLS 1.0
      - TLS 1.1

  cipher:
    minKeySize: 256
    requireForwardSecrecy: true
    bannedAlgorithms:
      - 3DES
      - RC4
      - MD5
      - SHA1
      - DES
      - EXPORT
      - NULL
      - ANON
    allowedCipherSuites:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
      - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

  certificate:
    minValidityDays: 30
    maxValidityDays: 397
    minRsaKeySize: 3072
    minEccKeySize: 384
    bannedSignatureAlgorithms:
      - SHA1
      - MD5
    allowSelfSigned: false
    requireCt: true

  quantum:
    requireHybridKeyExchange: false
    minQuantumScore: 25
    cnsa2TargetYear: 2027
```

## Using Custom Policies

```bash
# Apply custom policy
tlsanalyzer example.com --policy-file financial-services-policy.yaml

# With JSON output
tlsanalyzer example.com --policy-file my-policy.yaml --format json

# Batch scanning with custom policy
tlsanalyzer --targets hosts.txt --policy-file my-policy.yaml --format html -o report.html
```

## Policy Inheritance

Use `extends` to inherit from built-in policies and override specific rules:

```yaml
name: my-strict-policy
version: "1.0"
description: Strict policy with custom certificate requirements
extends: strict

rules:
  certificate:
    minValidityDays: 90
    maxValidityDays: 397
    requireCt: true
```

Every key the file sets wins; every key it omits is inherited from the base
policy. Above, the certificate validity and transparency requirements are this
file's, and the protocol, cipher and quantum rules are `strict`'s.

Run `tlsanalyzer print-policy strict` to see exactly what is being inherited.

## Compliance Checking in CI/CD

`tlsanalyzer` exits non-zero when a policy is not satisfied, so it can gate a
pipeline directly:

| Exit code | Meaning |
|-----------|---------|
| 0 | Scanned, and any policy applied was fully evaluated and satisfied |
| 1 | The scan could not be completed |
| 2 | A policy was applied and the target did not satisfy it, or the policy could not be fully evaluated |

Exit code 2 also covers an evaluation that skipped a rule, because a verdict
that skipped rules has established compliance with the part of the policy that
ran and not with the policy. The report lists any such rule under
"Not evaluated".

```bash
# Fails the job when the policy is not satisfied
tlsanalyzer api.example.com --policy-file my-policy.yaml

# Get compliance score
SCORE=$(tlsanalyzer api.example.com --policy-file my-policy.yaml --format json | \
  jq -r '.policyResult.score')
echo "Compliance Score: $SCORE/100"

# Check specific violations
tlsanalyzer api.example.com --policy-file my-policy.yaml --format json | \
  jq '.policyResult.violations[]'
```

## Policy Validation

A policy file is checked before any scan runs, and a policy that could not be
understood is refused rather than applied. Refused: a file with no YAML
document, a policy with no `name`, a policy with no rules after any inheritance,
a key the schema does not define, and an `extends` naming a policy that does not
exist.

This matters because the alternative is worse than an error. An empty file used
to report `COMPLIANT 100/100` and exit 0 on a host that `--policy strict` failed
with 35 violations at the same moment, and a file whose keys were all misspelled
did the same.

```bash
# Print a built-in policy in exactly the shape --policy-file accepts
tlsanalyzer print-policy strict > my-policy.yaml

# Any problem with the file is reported before the scan, naming the YAML path
tlsanalyzer example.com --policy-file my-policy.yaml

# List the built-in policies
tlsanalyzer policies
```

`--policy` and `--policy-file` both name a policy, so passing both is an error
rather than one silently winning.

A file holding more than one YAML document is also refused. Only the first
document would be applied, so the rules in the rest would be discarded without a
word while the verdict named a policy that was only part of the file. Put each
policy in its own file. A leading or trailing `---` around a single document is
ordinary YAML and is accepted.

### Rules that only warn

Two rules report a warning and can never produce a violation:

| Rule | Why it only warns |
|---|---|
| `certificate.minValidityDays` | A certificate inside its renewal window is not misconfigured. Failing on it would fail every host running a 90-day certificate through the last month of its life. |
| `quantum.requirePqcCertificates` | No publicly trusted CA issues an ML-DSA or SLH-DSA certificate today, so no operator can remedy it. |

Both still appear in the report, and both still lower the policy score. Neither
changes the compliance verdict or the exit code.

Because neither can fail a policy, neither can be the only rule a policy
defines. A file whose rules are all drawn from that table is refused when it
loads, naming the rule at fault: such a policy would report `COMPLIANT` with
exit 0 against every host forever, including hosts the same scan had already
measured as not meeting it. Add at least one rule that can produce a violation,
or use `extends`. A policy that mixes these rules with enforceable ones is
unaffected.

## Best Practices

1. **Start with a built-in policy** and customize as needed
2. **Version your policies** to track changes
3. **Store policies in version control** alongside your infrastructure code
4. **Use different policies** for different environments (dev, staging, prod)
5. **Regularly review and update** policies as requirements change
6. **Test policies** on a sample of targets before rolling out
