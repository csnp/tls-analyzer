package scanner

import (
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// generateRecommendations creates prioritized, actionable recommendations.
func (s *Scanner) generateRecommendations(result *types.ScanResult) []types.Recommendation {
	var recs []types.Recommendation
	priority := 1

	// Critical: Quantum readiness.
	//
	// Only when the assessment actually ran. A suppressed check leaves
	// QuantumRisk zero-valued, and treating that as a low score produced a
	// priority-1 "enable hybrid post-quantum key exchange" recommendation for
	// servers that demonstrably already negotiate X25519MLKEM768, contradicting
	// the CNSA section of the same report. Not measured is not the same as
	// measured absent.
	if s.config.CheckQuantum && result.QuantumRisk.Score < 50 {
		recs = append(recs, types.Recommendation{
			Priority:    priority,
			Category:    "quantum",
			Title:       "Enable Hybrid Post-Quantum Key Exchange",
			Description: "Your TLS configuration uses classical key exchange algorithms vulnerable to quantum attacks. Enable X25519MLKEM768 hybrid key exchange to protect against harvest-now-decrypt-later attacks.",
			Impact:      "Protects current communications from future quantum decryption",
			Effort:      "medium",
			References: []string{
				"https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/",
				"https://www.cloudflare.com/learning/ssl/post-quantum-cryptography/",
			},
		})
		priority++
	}

	// High priority: Protocol issues
	for _, proto := range result.Protocols {
		if proto.Supported {
			switch proto.Version {
			case "TLS 1.0", "TLS 1.1":
				recs = append(recs, types.Recommendation{
					Priority:    priority,
					Category:    "protocol",
					Title:       "Disable " + proto.Version,
					Description: proto.Version + " is deprecated and has known vulnerabilities. Major browsers have dropped support.",
					Impact:      "Eliminates known attack vectors; improves compliance",
					Effort:      "low",
					References: []string{
						"https://datatracker.ietf.org/doc/rfc8996/",
					},
				})
				priority++
			}
		}
	}

	// TLS 1.3
	tls13Supported := false
	for _, proto := range result.Protocols {
		if proto.Version == "TLS 1.3" && proto.Supported {
			tls13Supported = true
			break
		}
	}
	if !tls13Supported {
		recs = append(recs, types.Recommendation{
			Priority:    priority,
			Category:    "protocol",
			Title:       "Enable TLS 1.3",
			Description: "TLS 1.3 provides improved security, privacy, and performance. It removes outdated cryptographic algorithms and reduces handshake latency.",
			Impact:      "Better security, faster connections, PQC hybrid support",
			Effort:      "low",
			References: []string{
				"https://datatracker.ietf.org/doc/rfc8446/",
			},
		})
		priority++
	}

	// Cipher suite recommendations
	hasWeakCiphers := false
	lacksPFS := false
	for _, cs := range result.CipherSuites {
		if cs.Deprecated {
			hasWeakCiphers = true
		}
		if !cs.ForwardSecrecy {
			lacksPFS = true
		}
	}

	if hasWeakCiphers {
		recs = append(recs, types.Recommendation{
			Priority:    priority,
			Category:    "cipher",
			Title:       "Remove Deprecated Cipher Suites",
			Description: "Deprecated cipher suites like 3DES, RC4, and those using MD5/SHA1 should be disabled.",
			Impact:      "Eliminates weak encryption options",
			Effort:      "low",
		})
		priority++
	}

	if lacksPFS {
		recs = append(recs, types.Recommendation{
			Priority:    priority,
			Category:    "cipher",
			Title:       "Require Forward Secrecy",
			Description: "Use only cipher suites with ECDHE or DHE key exchange to ensure forward secrecy. This prevents decryption of past sessions if the private key is compromised.",
			Impact:      "Past communications remain protected even if key is compromised",
			Effort:      "low",
		})
		priority++
	}

	// Certificate recommendations
	if result.Certificate != nil {
		cert := result.Certificate

		if cert.Expired {
			recs = append(recs, types.Recommendation{
				Priority:    1, // Always highest priority
				Category:    "certificate",
				Title:       "Renew Expired Certificate",
				Description: "The server certificate has expired. Users will see security warnings and may not be able to connect.",
				Impact:      "Critical - service may be inaccessible",
				Effort:      "low",
			})
		} else if cert.DaysUntilExpiry < 30 {
			recs = append(recs, types.Recommendation{
				Priority:    priority,
				Category:    "certificate",
				Title:       "Renew Certificate Soon",
				Description: "Certificate expires in less than 30 days. Plan renewal to avoid service disruption.",
				Impact:      "Prevents service disruption",
				Effort:      "low",
			})
			priority++
		}

		if cert.PublicKeyAlgorithm == "RSA" && cert.PublicKeyBits < 2048 {
			recs = append(recs, types.Recommendation{
				Priority:    priority,
				Category:    "certificate",
				Title:       "Use Stronger RSA Key",
				Description: "RSA key is less than 2048 bits. Reissue with at least 2048-bit key (4096-bit recommended for long-term security).",
				Impact:      "Stronger cryptographic protection",
				Effort:      "medium",
			})
			priority++
		}

		if containsAny(cert.SignatureAlgorithm, "SHA1", "MD5") {
			recs = append(recs, types.Recommendation{
				Priority:    priority,
				Category:    "certificate",
				Title:       "Use SHA-256 or Stronger Signature",
				Description: "Certificate uses weak signature algorithm. Reissue with SHA-256 or SHA-384 signature.",
				Impact:      "Prevents signature forgery attacks",
				Effort:      "medium",
			})
			priority++
		}

		// Future-looking: PQC certificate recommendation
		// Gated on the assessment having run, for the same reason as the key
		// exchange recommendation above: a suppressed check leaves the score at
		// zero, which must not be read as a measured low score.
		if s.config.CheckQuantum && !cert.QuantumSafe && result.QuantumRisk.Score < 80 {
			recs = append(recs, types.Recommendation{
				Priority:    priority,
				Category:    "quantum",
				Title:       "Plan for Post-Quantum Certificates",
				Description: "Current certificate uses quantum-vulnerable signatures. Monitor CA support for ML-DSA (FIPS 204) certificates and plan migration timeline.",
				Impact:      "Future-proofs authentication against quantum attacks",
				Effort:      "high",
				References: []string{
					"https://csrc.nist.gov/publications/detail/fips/204/final",
				},
			})
		}
	}

	return recs
}
