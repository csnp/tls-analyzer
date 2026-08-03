package scanner

import (
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// calculateGrade computes the overall TLS configuration grade.
func (s *Scanner) calculateGrade(result *types.ScanResult) types.Grade {
	var factors []types.GradeFactor
	totalScore := 0
	maxTotal := 0

	// Protocol score (max 25 points)
	protoScore, protoMax := scoreProtocols(result.Protocols)
	factors = append(factors, types.GradeFactor{
		Category: "Protocol Support",
		Score:    protoScore,
		MaxScore: protoMax,
		Details:  describeProtocolScore(result.Protocols),
	})
	totalScore += protoScore
	maxTotal += protoMax

	// Cipher score (max 25 points)
	cipherScore, cipherMax := scoreCiphers(result.CipherSuites)
	factors = append(factors, types.GradeFactor{
		Category: "Cipher Strength",
		Score:    cipherScore,
		MaxScore: cipherMax,
		Details:  describeCipherScore(result.CipherSuites),
	})
	totalScore += cipherScore
	maxTotal += cipherMax

	// Certificate score (max 25 points)
	certScore, certMax := scoreCertificate(result.Certificate)
	factors = append(factors, types.GradeFactor{
		Category: "Certificate",
		Score:    certScore,
		MaxScore: certMax,
		Details:  describeCertScore(result.Certificate),
	})
	totalScore += certScore
	maxTotal += certMax

	// Quantum readiness score (max 25 points).
	//
	// Only counted when the assessment actually ran. Skipping it with
	// --skip-quantum previously left the score at zero while still charging the
	// full 25 points against the total, so declining to run an analysis dropped
	// the grade a whole band and reported a quantum score of 0 for servers that
	// verifiably negotiate a hybrid ML-KEM group. A check that was not run
	// contributes neither points nor maximum.
	var skippedDimensions []string
	if s.config.CheckQuantum {
		quantumScore := result.QuantumRisk.Score / 4 // Scale 0-100 to 0-25
		factors = append(factors, types.GradeFactor{
			Category: "Quantum Readiness",
			Score:    quantumScore,
			MaxScore: 25,
			Details:  describeQuantumScore(result.QuantumRisk),
		})
		totalScore += quantumScore
		maxTotal += 25
	} else {
		// Excluding the dimension keeps the score honest about what it measured,
		// but it also renormalizes over the remaining dimensions, and quantum
		// readiness is the one most servers score worst on. So skipping it RAISES
		// the reported grade. Recording which dimension was dropped is what lets
		// the report say the number is not comparable with a full scan's.
		skippedDimensions = append(skippedDimensions, "Quantum Readiness")
	}

	// Normalize the dimensions to a percentage.
	dimensionScore := 0
	if maxTotal > 0 {
		dimensionScore = (totalScore * 100) / maxTotal
	}
	if dimensionScore > 100 {
		dimensionScore = 100
	}
	if dimensionScore < 0 {
		dimensionScore = 0
	}

	// Apply vulnerability penalties, and record them. The deduction is real and
	// consistently applied, but it was never reported, so a breakdown printing
	// "Protocol 10 + Cipher 15 + Certificate 25 + Quantum 16" under a headline of
	// 21/100 gave a reader no way to reconcile the two numbers.
	penalties, penaltyTotal := vulnerabilityPenalties(result.Vulnerabilities)

	finalScore := dimensionScore - penaltyTotal
	penaltyFloored := false
	if finalScore < 0 {
		finalScore = 0
		penaltyFloored = true
	}
	if finalScore > 100 {
		finalScore = 100
	}

	grade := types.Grade{
		Letter:  scoresToLetter(finalScore),
		Score:   finalScore,
		Factors: factors,

		DimensionScore:     dimensionScore,
		DimensionPoints:    totalScore,
		DimensionMaxPoints: maxTotal,
		SkippedDimensions:  skippedDimensions,

		VulnerabilityPenalty: penaltyTotal,
		Penalties:            penalties,
		PenaltyFloored:       penaltyFloored,

		// A skipped check leaves the penalty unmeasured, not zero. Recording
		// which it was is what stops "--skip-vulns" reading as an improvement:
		// on cloudflare.com it moved the reported grade from F (21/100) to
		// C (66/100) purely by declining to look.
		VulnerabilitiesAssessed: s.config.CheckVulns,
	}

	// Only assign a quantum letter when the assessment ran. Deriving one from a
	// zero-valued, never-populated assessment reported "QV" (quantum
	// vulnerable) for servers that verifiably negotiate a hybrid ML-KEM group.
	if s.config.CheckQuantum {
		grade.QuantumGrade = quantumScoreToLetter(result.QuantumRisk.Score)
	} else {
		grade.QuantumGrade = types.QuantumGradeNotAssessed
	}

	return grade
}

// vulnerabilityPenaltyPoints is the deduction applied per finding at each
// severity, in the order the breakdown prints them. LOW and INFO findings do not
// move the score, which is why they are absent rather than listed as zero.
var vulnerabilityPenaltyPoints = []struct {
	Severity types.Severity
	Points   int
}{
	{types.SeverityCritical, 30},
	{types.SeverityHigh, 15},
	{types.SeverityMedium, 5},
}

// vulnerabilityPenalties itemizes the score deduction by severity and returns
// the total. Splitting it out is what lets the report show the penalty as its
// own line instead of leaving it as the unexplained gap between the dimension
// subtotal and the headline score.
func vulnerabilityPenalties(vulns []types.Vulnerability) ([]types.GradePenalty, int) {
	counts := make(map[types.Severity]int, len(vulnerabilityPenaltyPoints))
	for _, v := range vulns {
		counts[v.Severity]++
	}

	var (
		itemized []types.GradePenalty
		total    int
	)
	for _, p := range vulnerabilityPenaltyPoints {
		count := counts[p.Severity]
		if count == 0 {
			continue
		}
		points := count * p.Points
		itemized = append(itemized, types.GradePenalty{
			Severity:    p.Severity,
			Count:       count,
			PointsEach:  p.Points,
			PointsTotal: points,
		})
		total += points
	}

	return itemized, total
}

func scoreProtocols(protocols []types.Protocol) (int, int) {
	score := 0
	maxScore := 25

	tls13 := false
	tls12 := false
	tls11 := false
	tls10 := false

	for _, p := range protocols {
		if p.Supported {
			switch p.Version {
			case "TLS 1.3":
				tls13 = true
			case "TLS 1.2":
				tls12 = true
			case "TLS 1.1":
				tls11 = true
			case "TLS 1.0":
				tls10 = true
			}
		}
	}

	// TLS 1.3 carries the full credit for this dimension on its own.
	//
	// The previous model added 15 for TLS 1.3 and a further 10 for TLS 1.2, so a
	// TLS 1.3-only server could not score above 15 of 25 and turning TLS 1.2 off
	// cost ten points. That is the configuration this tool's own `strict` and
	// `cnsa-2.0-2030` policies require, so following its advice lowered its grade,
	// and the best achievable protocol posture was structurally denied the top of
	// the dimension. TLS 1.2 alongside TLS 1.3 is neither a bonus nor a penalty:
	// it is still a secure protocol, and its presence is what the policy layer is
	// for. Only deprecated versions move the score down.
	if tls13 {
		score += 25
	} else if tls12 {
		score += 10 // Secure, but not modern.
	}
	if tls11 {
		score -= 5 // Penalty for TLS 1.1
	}
	if tls10 {
		score -= 10 // Larger penalty for TLS 1.0
	}

	if score < 0 {
		score = 0
	}
	if score > maxScore {
		score = maxScore
	}

	return score, maxScore
}

// scoreCiphers grades the cipher configuration by its weakest accepted suite.
//
// An attacker who can influence negotiation will steer it toward the weakest
// suite the server still accepts, so the security of the configuration is the
// security of that suite, not of the best one. This previously awarded bonuses
// per suite and saturated at the maximum: once the scanner began enumerating
// the full list rather than reporting only the negotiated suite, a server
// offering non-forward-secret RSA suites still scored 25/25 while the policy
// evaluator listed sixteen violations against the same configuration.
func scoreCiphers(ciphers []types.CipherSuite) (int, int) {
	maxScore := 25

	if len(ciphers) == 0 {
		return 0, maxScore
	}

	var (
		anyWithoutForwardSecrecy bool
		anyDeprecated            bool
		anyBelow128              bool
		strongest                int
	)

	for _, cs := range ciphers {
		if !cs.ForwardSecrecy {
			anyWithoutForwardSecrecy = true
		}
		if cs.Deprecated {
			anyDeprecated = true
		}
		if cs.Bits > 0 && cs.Bits < 128 {
			anyBelow128 = true
		}
		if cs.Bits > strongest {
			strongest = cs.Bits
		}
	}

	score := maxScore
	if anyWithoutForwardSecrecy {
		// Recorded traffic stays decryptable if the server key is ever
		// compromised, which is the same exposure post-quantum work targets.
		score -= 10
	}
	if anyDeprecated {
		// Accepting a broken cipher such as RC4, MD5 or 3DES undermines the
		// configuration regardless of what else is offered, since negotiation
		// can be steered toward it. This dimension scores zero rather than
		// taking a proportional penalty.
		return 0, maxScore
	}
	if anyBelow128 {
		score -= 10
	}
	if strongest < 256 {
		// CNSA 2.0 requires AES-256 for symmetric encryption.
		score -= 5
	}

	// Normalize to max score
	if score > maxScore {
		score = maxScore
	}
	if score < 0 {
		score = 0
	}

	return score, maxScore
}

func scoreCertificate(cert *types.Certificate) (int, int) {
	maxScore := 25

	if cert == nil {
		return 0, maxScore
	}

	score := 15 // Base score for having a valid cert

	// Validity. Both ends of the window score zero: a certificate whose validity
	// has not started is refused by every client exactly as an expired one is,
	// and it previously scored 25 of 25 because the chain check steps aside for
	// it and nothing else looked at notBefore.
	if cert.Expired || cert.NotYetValid {
		return 0, maxScore
	}

	// A certificate that is not valid for the name it was asked for, or that
	// does not chain to a trusted root, cannot authenticate the connection at
	// all: every client refuses it outright, exactly as it refuses an expired
	// one. So the dimension scores zero for the same reason expiry does.
	// wrong.host.badssl.com and untrusted-root.badssl.com both scored 25 of 25
	// before this, which told an operator the certificate was perfect.
	if cert.NameMatch == types.CheckFailed || cert.ChainTrust == types.CheckFailed {
		return 0, maxScore
	}

	if cert.DaysUntilExpiry > 30 {
		score += 5
	}

	// Key strength
	if cert.PublicKeyAlgorithm == "RSA" && cert.PublicKeyBits >= 4096 {
		score += 5
	} else if cert.PublicKeyAlgorithm == "RSA" && cert.PublicKeyBits >= 2048 {
		score += 3
	} else if cert.PublicKeyAlgorithm == "ECDSA" {
		score += 5 // ECDSA is more efficient
	}

	// Signature algorithm
	if containsAny(cert.SignatureAlgorithm, "SHA256", "SHA384", "SHA512") {
		score += 5
	}
	if containsAny(cert.SignatureAlgorithm, "SHA1", "MD5") {
		score -= 10
	}

	// Self-signed penalty
	if cert.IsSelfSigned {
		score -= 5
	}

	if score > maxScore {
		score = maxScore
	}
	if score < 0 {
		score = 0
	}

	return score, maxScore
}

func scoresToLetter(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func quantumScoreToLetter(score int) string {
	switch {
	case score >= 80:
		return "Q+" // Quantum ready
	case score >= 50:
		return "Q" // Partially quantum ready
	case score >= 20:
		return "Q-" // Limited quantum protection
	default:
		return "QV" // Quantum vulnerable
	}
}

func describeProtocolScore(protocols []types.Protocol) string {
	tls13 := false
	deprecated := false

	for _, p := range protocols {
		if p.Supported {
			if p.Version == "TLS 1.3" {
				tls13 = true
			}
			if p.Version == "TLS 1.0" || p.Version == "TLS 1.1" {
				deprecated = true
			}
		}
	}

	if tls13 && !deprecated {
		return "Excellent: TLS 1.3 supported, no deprecated protocols"
	}
	if tls13 && deprecated {
		return "Good: TLS 1.3 supported but deprecated protocols still enabled"
	}
	if !tls13 {
		return "Needs improvement: TLS 1.3 not supported"
	}
	return "Unknown"
}

func describeCipherScore(ciphers []types.CipherSuite) string {
	if len(ciphers) == 0 {
		return "No cipher information available"
	}

	allPFS := true
	hasDeprecated := false
	strongEncryption := true

	for _, cs := range ciphers {
		if !cs.ForwardSecrecy {
			allPFS = false
		}
		if cs.Deprecated {
			hasDeprecated = true
		}
		if cs.Bits < 128 {
			strongEncryption = false
		}
	}

	if allPFS && !hasDeprecated && strongEncryption {
		return "Excellent: All ciphers have forward secrecy and strong encryption"
	}
	if hasDeprecated {
		return "Poor: Deprecated cipher suites are enabled"
	}
	if !allPFS {
		return "Needs improvement: Some ciphers lack forward secrecy"
	}
	return "Good cipher configuration"
}

func describeCertScore(cert *types.Certificate) string {
	if cert == nil {
		return "No certificate found"
	}
	if cert.Expired {
		return "Critical: Certificate has expired"
	}
	if cert.NotYetValid {
		return "Critical: Certificate is not yet valid"
	}
	if cert.NameMatch == types.CheckFailed {
		return "Critical: Certificate is not valid for " + cert.RequestedName
	}
	if cert.ChainTrust == types.CheckFailed {
		return "Critical: Certificate does not chain to a trusted root"
	}
	if cert.DaysUntilExpiry < 30 {
		return "Warning: Certificate expiring soon"
	}
	if cert.IsSelfSigned {
		return "Note: Self-signed certificate"
	}

	// Say what was checked rather than asserting more than that. This line read
	// "Valid certificate from trusted CA" while nothing verified the chain at
	// all, so untrusted-root.badssl.com carried it too.
	if cert.NameMatch == types.CheckPassed && cert.ChainTrust == types.CheckPassed {
		return "Certificate is current, valid for " + cert.RequestedName + ", and chains to a trusted root"
	}
	return "Certificate is current; name or chain verification did not run"
}

func describeQuantumScore(qr types.QuantumRiskAssessment) string {
	switch qr.Level {
	case types.RiskCritical:
		return "Critical: No quantum protection, vulnerable to future attacks"
	case types.RiskHigh:
		return "High risk: Minimal quantum protection"
	case types.RiskMedium:
		return "Medium risk: Partial quantum protection"
	case types.RiskLow:
		return "Good: Hybrid or full PQC protection in place"
	default:
		return "Unknown quantum readiness"
	}
}
