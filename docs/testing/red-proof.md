# How a regression test in this repository is red-proved

A regression test is worth its runtime only if it fails on the code before the
fix. This file records how that is established here, and why the method changed
in 0.4.1.

## The method that does not work

Twelve test files in the 0.4.0 release tree carried a comment of this shape:

> This file names nothing that did not already exist, so it compiles against the
> pre-fix sources and fails there on behaviour.

Eleven of the twelve are false, and the twelfth is true by luck rather than by
design. Measured in 0.4.1 by copying each file alone into a pristine tree at
`a869357`, the commit before the release, and compiling:

| file | claim | actual |
|---|---|---|
| `internal/scanner/certificate_checks_test.go` | compiles | compiles |
| `internal/analyzer/policy_multi_document_test.go` | compiles | `undefined: writePolicyFile` |
| `internal/analyzer/policy_remediation_test.go` | compiles | `undefined: scanForRuleValues` |
| `internal/analyzer/policy_rule_values_test.go` | compiles | `undefined: types.CheckPassed` |
| `internal/analyzer/policy_rule_values_fields_test.go` | its companion compiles | its companion does not |
| `internal/analyzer/policy_scalar_forms_test.go` | compiles | `undefined: writePolicyFile` |
| `internal/analyzer/policy_skipped_rules_test.go` | compiles | `undefined: types.CheckPassed` |
| `internal/analyzer/policy_unperformed_certificate_checks_test.go` | compiles | `undefined: types.CheckResult` |
| `internal/reporter/unmeasured_quantum_test.go` | compiles | `undefined: healthyCert` |
| `internal/scanner/certificate_chain_position_test.go` | compiles | `undefined: verifyCertificateChain` |
| `internal/scanner/certificate_validity_window_test.go` | compiles | `undefined: issueLeaf` |
| `internal/scanner/expiring_last_day_test.go` | compiles | `undefined: types.CheckPassed` |

The cause is structural rather than careless. 0.4.0 landed as a single squashed
commit, so the production change, the new types, the test helpers and the tests
all arrived at the same instant. There is no pre-fix tree in this repository for
any of that release's tests to compile against, and there is no per-fix parent to
fall back to, because the intermediate commits do not exist here.

A proof that requires objects only one machine ever had is not a proof anyone
can repeat. Any comment of this shape is now treated as a defect.

## The method that does work

Prove the test red by reverting the production behaviour it is named for, in the
working tree, and watching the test fail. This pins the behaviour rather than a
property of one historical tree, it can be rerun by anyone at any commit, and it
keeps working after a squash, a rebase or a repository move.

Rules that make the result mean something:

1. **Revert exactly one property per mutation.** A mutation that changes two
   things cannot tell you which one the test was measuring.
2. **Restore by editing back, never with `git checkout -- <file>`.** The mutant
   and the fix live in the same file, so a file-level restore takes both. Work in
   a throwaway copy of the tree if that is easier.
3. **A build failure is not a kill.** If the mutated tree does not compile, the
   test proved nothing about the assertion.
4. **A surviving mutation means the distinction is untested, not unnecessary.**
   Add the test that pins it. Deleting the code because breaking it stayed green
   removes a real behaviour and leaves nothing to catch its absence.
5. **Say which mutation** in the file's header comment, precisely enough for the
   next person to reapply it. "Reverting the guard kills it" is not reusable;
   "set `NotYetValid` to false rather than deriving it from
   `now.Before(NotBefore)`" is.

Every red-proof claim in this repository now names its mutation. The claims are
kept honest by `TestNoTestFileClaimsAnUnrepeatableRedProof`, which fails if the
compile-against-the-pre-fix-sources phrasing reappears.

## Worked examples

| test | mutation that kills it |
|---|---|
| `TestUnrecognisedProtocolVersionValuesAreRefused` | `validateProtocolVersionValues` stops checking its fields |
| `TestAnAlgorithmValueThatNormalizesToNothingIsRefused` | `validateAlgorithmValues` stops checking its fields |
| `TestEverySpellingOfZeroIsRefusedAsANonRule` | `fieldConstrains` returns true without reading the decoded value |
| `TestANotYetValidCertificateIsNotScoredAsHealthy` | `NotYetValid` set to false instead of `now.Before(NotBefore)` |
| `TestAFailedScanScrubsTheErrorAndStillUnwraps` | `sanitize.WrapError` dropped from the `scan failed` wrap |
| `TestARefusalCannotBeMadeArbitrarilyLongByThePolicyFile` | the name cap moved back to the end of `LoadPolicy` |
| `TestEveryUntrustedChainShapeProducesExactlyOneHighFinding` | the two suppressions restored to their 0.4.0 form |
| `TestNoSurfaceDescribesAHostItNeverReachedAsMeasured` | any one renderer's unreached branch removed |
