package scanner

import (
	"fmt"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// checkVulnerabilities analyzes the scan result for known vulnerabilities.
func (s *Scanner) checkVulnerabilities(result *types.ScanResult) []types.Vulnerability {
	var vulns []types.Vulnerability

	// Check for deprecated protocols
	for _, proto := range result.Protocols {
		if proto.Supported {
			switch proto.Version {
			case "TLS 1.0":
				vulns = append(vulns, types.Vulnerability{
					ID:          "TLS10_ENABLED",
					Name:        "TLS 1.0 Enabled",
					Severity:    types.SeverityHigh,
					Description: "TLS 1.0 is deprecated and has known vulnerabilities including BEAST and POODLE.",
					CVE:         "CVE-2011-3389",
					Remediation: "Disable TLS 1.0 and enable TLS 1.2 or TLS 1.3.",
					References:  []string{"https://datatracker.ietf.org/doc/rfc8996/"},
				})
			case "TLS 1.1":
				vulns = append(vulns, types.Vulnerability{
					ID:          "TLS11_ENABLED",
					Name:        "TLS 1.1 Enabled",
					Severity:    types.SeverityMedium,
					Description: "TLS 1.1 is deprecated. While more secure than TLS 1.0, it lacks modern cipher suites.",
					Remediation: "Disable TLS 1.1 and enable TLS 1.2 or TLS 1.3.",
					References:  []string{"https://datatracker.ietf.org/doc/rfc8996/"},
				})
			case "SSL 3.0":
				vulns = append(vulns, types.Vulnerability{
					ID:          "SSL3_ENABLED",
					Name:        "SSL 3.0 Enabled",
					Severity:    types.SeverityCritical,
					Description: "SSL 3.0 is severely deprecated and vulnerable to POODLE attack.",
					CVE:         "CVE-2014-3566",
					Remediation: "Disable SSL 3.0 immediately.",
					References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-3566"},
				})
			}
		}
	}

	// Check TLS 1.3 support
	tls13Supported := false
	for _, proto := range result.Protocols {
		if proto.Version == "TLS 1.3" && proto.Supported {
			tls13Supported = true
			break
		}
	}
	if !tls13Supported {
		vulns = append(vulns, types.Vulnerability{
			ID:          "NO_TLS13",
			Name:        "TLS 1.3 Not Supported",
			Severity:    types.SeverityMedium,
			Description: "TLS 1.3 provides improved security and performance. Not supporting it limits modern security features.",
			Remediation: "Enable TLS 1.3 support on the server.",
			References:  []string{"https://datatracker.ietf.org/doc/rfc8446/"},
		})
	}

	// Check cipher suites
	for _, cs := range result.CipherSuites {
		if cs.Deprecated {
			vulns = append(vulns, types.Vulnerability{
				ID:          "DEPRECATED_CIPHER_" + cs.Name,
				Name:        "Deprecated Cipher Suite: " + cs.Name,
				Severity:    types.SeverityHigh,
				Description: cs.DeprecatedReason,
				Remediation: "Remove " + cs.Name + " from the cipher suite configuration.",
			})
		}

		// Check for non-forward-secrecy ciphers
		if !cs.ForwardSecrecy && cs.KeyExchange == "RSA" {
			vulns = append(vulns, types.Vulnerability{
				ID:          "NO_PFS_" + cs.Name,
				Name:        "No Forward Secrecy: " + cs.Name,
				Severity:    types.SeverityMedium,
				Description: "Cipher suite uses RSA key exchange without forward secrecy. If the private key is compromised, all past sessions can be decrypted.",
				Remediation: "Prefer ECDHE or DHE key exchange for forward secrecy.",
			})
		}

		// Check for weak key sizes
		if cs.Bits > 0 && cs.Bits < 128 {
			vulns = append(vulns, types.Vulnerability{
				ID:          "WEAK_CIPHER_" + cs.Name,
				Name:        "Weak Cipher Strength: " + cs.Name,
				Severity:    types.SeverityHigh,
				Description: "Cipher suite uses less than 128-bit encryption, which is considered weak.",
				Remediation: "Use cipher suites with at least 128-bit encryption (256-bit preferred).",
			})
		}
	}

	// Check certificate
	if result.Certificate != nil {
		cert := result.Certificate

		// Expired certificate
		if cert.Expired {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_EXPIRED",
				Name:        "Certificate Expired",
				Severity:    types.SeverityCritical,
				Description: "The server certificate has expired. Browsers will show security warnings.",
				Remediation: "Renew the certificate immediately.",
			})
		}

		// Not yet valid. The chain check declines to run for a certificate
		// outside its validity window on the grounds that the window is reported
		// on its own, so this end of the window has to be reported here or the
		// certificate is scored as though nothing were wrong with it.
		if cert.NotYetValid {
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_NOT_YET_VALID",
				Name:     "Certificate Not Yet Valid",
				Severity: types.SeverityCritical,
				Description: "The server certificate's validity period has not started, so " +
					"clients will refuse it exactly as they refuse an expired one.",
				Remediation: "Check the certificate's notBefore date and the clock on this " +
					"machine, then deploy a certificate that is valid now.",
			})
		}

		// Expiring soon. The guard exists so an EXPIRED certificate is not also
		// reported as expiring soon, and a not-yet-valid one has a positive count
		// and walked straight through it, so a short future window produced two
		// findings for one condition, a double penalty, and a "plan renewal"
		// instruction pointing the wrong way.
		//
		// The guard now asks whether the certificate is expired, which is the
		// question the previous DaysUntilExpiry > 0 was standing in for. That
		// stand-in was wrong for the last day of a certificate's life:
		// DaysUntilExpiry truncates, so a certificate with eleven hours left counts
		// 0, cleared neither the > 0 test nor the expiry test, and produced no
		// finding at all in the window where renewal is most urgent.
		if !cert.NotYetValid && !cert.Expired && cert.DaysUntilExpiry < 30 {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_EXPIRING",
				Name:        "Certificate Expiring Soon",
				Severity:    types.SeverityMedium,
				Description: "The certificate will expire in less than 30 days.",
				Remediation: "Plan certificate renewal before expiration.",
			})
		}

		// Certificate presented for a different name
		if cert.NameMatch == types.CheckFailed {
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_NAME_MISMATCH",
				Name:     "Certificate Name Mismatch",
				Severity: types.SeverityHigh,
				Description: fmt.Sprintf(
					"The certificate served for %s is not valid for that name (%s). A client "+
						"that verifies the connection refuses it, so this name cannot be reached "+
						"over TLS by a normal browser or API client.",
					cert.RequestedName, cert.NameMismatchReason),
				Remediation: fmt.Sprintf(
					"Install a certificate whose subject alternative names include %s, or point "+
						"clients at a name the presented certificate already covers.",
					cert.RequestedName),
			})
		}

		// Chain does not build to a trusted root. Reported only when the
		// certificate is not self-signed, because the self-signed finding below
		// is the more specific diagnosis of the same condition and stating it
		// twice would deduct twice for one decision.
		if cert.ChainTrust == types.CheckFailed && !cert.IsSelfSigned {
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_CHAIN_UNTRUSTED",
				Name:     "Certificate Chain Not Trusted",
				Severity: types.SeverityHigh,
				Description: fmt.Sprintf(
					"The presented certificate chain does not build to a root in this host's "+
						"trust store (%s). A client that verifies the connection refuses it.",
					cert.ChainTrustReason),
				Remediation: "Serve the full chain including every intermediate, and use a " +
					"certificate from a CA the intended clients trust. If this host is served " +
					"by an internal CA, that CA has to be installed in the trust store of the " +
					"machine running the scan for this check to pass.",
			})
		}

		// Self-signed certificate
		if cert.IsSelfSigned && !cert.IsCA {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_SELF_SIGNED",
				Name:        "Self-Signed Certificate",
				Severity:    types.SeverityMedium,
				Description: "Self-signed certificates are not trusted by browsers and clients by default.",
				Remediation: "Use a certificate from a trusted Certificate Authority.",
			})
		}

		// Weak signature algorithm
		if containsAny(cert.SignatureAlgorithm, "SHA1", "MD5", "MD2") {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_WEAK_SIG",
				Name:        "Weak Certificate Signature",
				Severity:    types.SeverityHigh,
				Description: "Certificate uses a weak signature algorithm: " + cert.SignatureAlgorithm,
				Remediation: "Reissue the certificate with SHA-256 or stronger signature.",
				References:  []string{"https://shattered.io/"},
			})
		}

		// Weak RSA key
		if cert.PublicKeyAlgorithm == "RSA" && cert.PublicKeyBits < 2048 {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_WEAK_KEY",
				Name:        "Weak RSA Key Size",
				Severity:    types.SeverityHigh,
				Description: "RSA key is less than 2048 bits, which is considered weak.",
				Remediation: "Reissue the certificate with at least 2048-bit RSA key (4096-bit recommended).",
			})
		}
	}

	return vulns
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
