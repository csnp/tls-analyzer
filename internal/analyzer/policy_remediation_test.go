package analyzer

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The 0.4.0 release test found that the banned-signature-algorithm violation
// carried a hardcoded remediation, "Reissue certificate with SHA-256 or stronger
// signature", whatever the policy actually banned. The shipped `strict` policy
// bans SHA1, MD5 AND SHA256, because it is aiming at SHA-384 or better, so a
// scan of any ECDSA-SHA256 certificate under `strict` printed:
//
//	Expected: SHA256 not used | Actual: ECDSA-SHA256
//	Fix: Reissue certificate with SHA-256 or stronger signature
//
// Following that fix reproduces the violation it claims to resolve. This is the
// dead-end remediation class this toolkit already has a rule about: every
// finding has to name a next step that actually works.
//
// This file names nothing that did not already exist, so it compiles against the
// pre-fix sources and fails there on behaviour rather than on a build error.

// certScanForRemediation is a scan whose certificate is signed with
// ECDSA-SHA256, the case `strict` flags.
func certScanForRemediation() *types.ScanResult {
	scan := scanForRuleValues()
	scan.Certificate.SignatureAlgorithm = "ECDSA-SHA256"
	return scan
}

func bannedSignatureViolations(pr *types.PolicyResult) []types.PolicyViolation {
	var out []types.PolicyViolation
	for _, v := range pr.Violations {
		if v.Rule == "certificate.bannedSignatureAlgorithms" {
			out = append(out, v)
		}
	}
	return out
}

// TestBannedSignatureRemediationNeverRecommendsABannedAlgorithm states the
// general property rather than pinning one string: whatever the policy bans, the
// remediation must not tell the operator to reissue with it. Asserting the
// property means a later edit that swaps one hardcoded algorithm for another
// still fails.
func TestBannedSignatureRemediationNeverRecommendsABannedAlgorithm(t *testing.T) {
	cases := []struct {
		name   string
		banned []string
	}{
		// The shipped `strict` policy, which is how a user reaches this.
		{"strict bans SHA256 as well as the legacy digests", []string{"SHA1", "MD5", "SHA256"}},
		// A CNSA-shaped policy that wants SHA-384 or better.
		{"policy banning every digest below SHA-384", []string{"SHA1", "SHA224", "SHA256"}},
		// The narrow case: only the algorithm actually in use is banned.
		{"policy banning only the observed algorithm", []string{"SHA256"}},
		// The first candidates are banned, so the suggestion loop has to skip
		// past them. Without a case like this the not-banned guard is never
		// exercised and a mutation deleting it survives.
		// SHA256 is what makes the violation fire against this certificate; the
		// rest push the suggestion past the first two candidates.
		{"policy banning the strongest candidates too", []string{"SHA256", "ML-DSA", "SHA512"}},
		{"policy banning all but the weakest candidate", []string{"ML-DSA", "SHA512", "SHA384", "ECDSA"}},
	}

	e := NewPolicyEvaluator()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			pr := e.Evaluate(certScanForRemediation(), &types.Policy{
				Name: "t",
				Rules: types.PolicyRules{
					Certificate: types.CertificateRules{
						BannedSignatureAlgorithms: tt.banned,
					},
				},
			})

			violations := bannedSignatureViolations(pr)
			if len(violations) == 0 {
				t.Fatalf("no certificate.bannedSignatureAlgorithms violation was raised for %v, "+
					"so this test cannot observe the remediation it exists to check", tt.banned)
			}

			for _, v := range violations {
				if v.Remediation == "" {
					t.Errorf("violation %q carries no remediation at all", v.Expected)
					continue
				}
				for _, banned := range tt.banned {
					if containsFold(v.Remediation, banned) {
						t.Errorf("the remediation recommends an algorithm this policy bans.\n"+
							"  policy bans: %v\n  remediation: %q\n  names banned value: %q\n"+
							"Following this fix reproduces the violation.",
							tt.banned, v.Remediation, banned)
					}
				}
			}
		})
	}
}

// TestBannedSignatureRemediationNamesTheRequirementWhenThePolicyStatesOne is the
// positive half: when the policy also says what it DOES want, the remediation
// should point at that rather than at a generic instruction.
func TestBannedSignatureRemediationNamesTheRequirementWhenThePolicyStatesOne(t *testing.T) {
	e := NewPolicyEvaluator()
	pr := e.Evaluate(certScanForRemediation(), &types.Policy{
		Name: "t",
		Rules: types.PolicyRules{
			Certificate: types.CertificateRules{
				BannedSignatureAlgorithms:   []string{"SHA256"},
				RequiredSignatureAlgorithms: []string{"ECDSA-SHA384"},
			},
		},
	})

	violations := bannedSignatureViolations(pr)
	if len(violations) == 0 {
		t.Fatal("no banned-signature violation was raised, so the remediation cannot be checked")
	}
	if !containsFold(violations[0].Remediation, "ECDSA-SHA384") {
		t.Errorf("the policy states what it requires, so the remediation should name it.\n"+
			"  required:    ECDSA-SHA384\n  remediation: %q", violations[0].Remediation)
	}
}

// TestSuggestedSignatureIsObtainableToday guards the tool's own rule that advice
// must never name work the operator cannot perform. No publicly trusted CA
// issues a post-quantum certificate, so the suggestion list must not offer one:
// the first version of this fix replaced a self-contradictory remediation with an
// unobtainable one, which is the same defect wearing a different hat.
//
// A policy that explicitly requires a PQC signature is a different case and is
// covered by TestBannedSignatureRemediationNamesTheRequirementWhenThePolicyStatesOne.
func TestSuggestedSignatureIsObtainableToday(t *testing.T) {
	for _, candidate := range signatureUpgradePreference {
		for _, pqc := range []string{"ML-DSA", "SLH-DSA", "Falcon", "Dilithium"} {
			if containsFold(candidate, pqc) {
				t.Errorf("the suggestion list offers %q, which names the post-quantum "+
					"algorithm %q that no publicly trusted CA issues; an operator "+
					"cannot act on this advice", candidate, pqc)
			}
		}
	}

	// And observe it end to end on the shipped `strict` policy, which is how a
	// user reaches this remediation.
	pr := NewPolicyEvaluator().Evaluate(certScanForRemediation(), &types.Policy{
		Name: "t",
		Rules: types.PolicyRules{
			Certificate: types.CertificateRules{
				BannedSignatureAlgorithms: []string{"SHA1", "MD5", "SHA256"},
			},
		},
	})
	violations := bannedSignatureViolations(pr)
	if len(violations) == 0 {
		t.Fatal("no banned-signature violation was raised under a strict-shaped policy")
	}
	if containsFold(violations[0].Remediation, "ML-DSA") {
		t.Errorf("the remediation tells the operator to deploy a certificate no CA "+
			"issues: %q", violations[0].Remediation)
	}
}

// TestRemediationFallsBackWhenEveryCandidateIsBanned covers the end of the
// suggestion list. A policy that bans every algorithm the tool could suggest
// must still get a next step, and that step must not name any of them.
func TestRemediationFallsBackWhenEveryCandidateIsBanned(t *testing.T) {
	banned := append([]string{}, signatureUpgradePreference...)

	pr := NewPolicyEvaluator().Evaluate(certScanForRemediation(), &types.Policy{
		Name: "t",
		Rules: types.PolicyRules{
			Certificate: types.CertificateRules{BannedSignatureAlgorithms: banned},
		},
	})

	violations := bannedSignatureViolations(pr)
	if len(violations) == 0 {
		t.Fatal("banning every candidate raised no violation, so the fallback cannot be observed")
	}
	rem := violations[0].Remediation
	if rem == "" {
		t.Fatal("no remediation was given when every candidate is banned")
	}
	for _, b := range banned {
		if containsFold(rem, b) {
			t.Errorf("the fallback remediation names a banned algorithm %q: %q", b, rem)
		}
	}
}

// TestAcceptanceRemediationStillGivenForLegacyDigestBans is the acceptance
// control. Tightening the remediation must not empty it for the ordinary case of
// banning SHA1 on a certificate that uses SHA1: a finding with no next step is
// the same defect mirrored.
func TestAcceptanceRemediationStillGivenForLegacyDigestBans(t *testing.T) {
	scan := scanForRuleValues()
	scan.Certificate.SignatureAlgorithm = "SHA1-RSA"

	pr := NewPolicyEvaluator().Evaluate(scan, &types.Policy{
		Name: "t",
		Rules: types.PolicyRules{
			Certificate: types.CertificateRules{
				BannedSignatureAlgorithms: []string{"SHA1"},
			},
		},
	})

	violations := bannedSignatureViolations(pr)
	if len(violations) == 0 {
		t.Fatal("banning SHA1 against a SHA1-RSA certificate raised no violation")
	}
	if violations[0].Remediation == "" {
		t.Error("the remediation is empty; every finding must carry a next step")
	}
	if containsFold(violations[0].Remediation, "SHA1") {
		t.Errorf("the remediation still names the banned algorithm: %q", violations[0].Remediation)
	}
}
