package reporter

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// HTMLReporter outputs results as an HTML report.
type HTMLReporter struct {
	IncludeCSS bool // Include CSS inline (for standalone reports)
}

// Report writes the scan result as HTML.
func (r *HTMLReporter) Report(w io.Writer, result *types.ScanResult) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"gradeClass":    gradeClass,
		"severityClass": severityClass,
		"riskClass":     riskClass,
		"formatTime":    formatTime,
		"progressBar":   progressBar,
		"statusIcon":    statusIcon,
		// The icon and the badge answer the same question, so they read the
		// same predicate rather than each carrying its own copy of the version
		// list.
		"protocolIcon":         protocolIcon,
		"isDeprecatedProtocol": types.IsDeprecatedProtocol,
		// Shared with the text reporter so the two cannot describe the same
		// deduction differently.
		"describePenalties": describePenalties,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl.Execute(w, result)
}

// Format returns the format name.
func (r *HTMLReporter) Format() string {
	return "html"
}

func gradeClass(letter string) string {
	switch {
	case strings.HasPrefix(letter, "A"):
		return "grade-a"
	case letter == "B":
		return "grade-b"
	case letter == "C":
		return "grade-c"
	case letter == "D":
		return "grade-d"
	default:
		return "grade-f"
	}
}

func severityClass(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical:
		return "severity-critical"
	case types.SeverityHigh:
		return "severity-high"
	case types.SeverityMedium:
		return "severity-medium"
	case types.SeverityLow:
		return "severity-low"
	default:
		return "severity-info"
	}
}

func riskClass(level types.RiskLevel) string {
	switch level {
	case types.RiskCritical:
		return "risk-critical"
	case types.RiskHigh:
		return "risk-high"
	case types.RiskMedium:
		return "risk-medium"
	case types.RiskLow:
		return "risk-low"
	default:
		// A level this function does not recognise is not a low risk, it is an
		// unknown one. Defaulting to the reassuring class styled an empty risk
		// level green, which is how an assessment that never ran was painted as
		// the best possible outcome.
		return "risk-unknown"
	}
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05 MST")
}

func progressBar(score, max int) template.HTML {
	if max == 0 {
		max = 100
	}
	pct := (score * 100) / max
	class := "progress-good"
	if pct < 50 {
		class = "progress-bad"
	} else if pct < 75 {
		class = "progress-warn"
	}
	return template.HTML(fmt.Sprintf(
		`<div class="progress-bar"><div class="progress-fill %s" style="width: %d%%"></div><span class="progress-text">%d/%d</span></div>`,
		class, pct, score, max,
	))
}

func statusIcon(supported bool) template.HTML {
	if supported {
		return template.HTML(`<span class="status-icon status-good">✓</span>`)
	}
	return template.HTML(`<span class="status-icon status-bad">✗</span>`)
}

// protocolIcon distinguishes a protocol that is supported and current from one
// that is supported and deprecated. Both used to render as the same green
// check, so an HTML report showed TLS 1.0 and TLS 1.1 rows as good while the
// text report called them deprecated and the vulnerability list flagged TLS 1.0
// HIGH. The .status-warn class was already defined in the stylesheet and used
// nowhere, so the warning styling was intended and lost.
func protocolIcon(p types.Protocol) template.HTML {
	if !p.Supported {
		return template.HTML(`<span class="status-icon status-bad">✗</span>`)
	}
	if types.IsDeprecatedProtocol(p.Version) {
		return template.HTML(`<span class="status-icon status-warn">⚠</span>`)
	}
	return template.HTML(`<span class="status-icon status-good">✓</span>`)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QRAMM TLS Analysis Report - {{.Target}}</title>
    <style>
        :root {
            --color-bg: #0f1419;
            --color-card: #1a1f2e;
            --color-border: #2d3748;
            --color-text: #e2e8f0;
            --color-text-dim: #718096;
            --color-accent: #667eea;
            --color-good: #48bb78;
            --color-warn: #ed8936;
            --color-bad: #f56565;
            --color-quantum: #9f7aea;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
            padding: 2rem;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: linear-gradient(135deg, var(--color-card) 0%, #2d3748 100%);
            border-radius: 12px;
            border: 1px solid var(--color-border);
        }

        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--color-quantum);
            margin-bottom: 0.5rem;
        }

        h1 { font-size: 2rem; margin-bottom: 1rem; }

        .target-info {
            color: var(--color-text-dim);
            font-size: 0.9rem;
        }

        .grades {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin: 2rem 0;
        }

        .grade-box {
            text-align: center;
            padding: 1.5rem 2rem;
            background: var(--color-card);
            border-radius: 12px;
            border: 2px solid var(--color-border);
        }

        .grade-label {
            font-size: 0.8rem;
            text-transform: uppercase;
            color: var(--color-text-dim);
            margin-bottom: 0.5rem;
        }

        .grade-letter {
            font-size: 3rem;
            font-weight: bold;
        }

        .grade-score {
            font-size: 0.9rem;
            color: var(--color-text-dim);
        }

        .grade-a { color: var(--color-good); border-color: var(--color-good); }
        .grade-b { color: var(--color-good); border-color: var(--color-good); }
        .grade-c { color: var(--color-warn); border-color: var(--color-warn); }
        .grade-d { color: var(--color-warn); border-color: var(--color-warn); }
        .grade-f { color: var(--color-bad); border-color: var(--color-bad); }

        .quantum-grade { border-color: var(--color-quantum); }
        .quantum-grade .grade-letter { color: var(--color-quantum); }

        section {
            background: var(--color-card);
            border-radius: 12px;
            border: 1px solid var(--color-border);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        h2 {
            font-size: 1.2rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--color-border);
        }

        h2.quantum { color: var(--color-quantum); }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--color-border);
        }

        th {
            font-size: 0.8rem;
            text-transform: uppercase;
            color: var(--color-text-dim);
        }

        .progress-bar {
            width: 150px;
            height: 20px;
            background: var(--color-border);
            border-radius: 4px;
            overflow: hidden;
            position: relative;
        }

        .progress-fill {
            height: 100%;
            transition: width 0.3s;
        }

        .progress-good { background: var(--color-good); }
        .progress-warn { background: var(--color-warn); }
        .progress-bad { background: var(--color-bad); }

        .progress-text {
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 0.75rem;
            font-weight: bold;
        }

        .status-icon {
            display: inline-block;
            width: 1.5rem;
            text-align: center;
        }

        .status-good { color: var(--color-good); }
        .status-bad { color: var(--color-bad); }
        .status-warn { color: var(--color-warn); }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }

        .severity-critical { background: #742a2a; color: #feb2b2; }
        .severity-high { background: #7b341e; color: #fbd38d; }
        .severity-medium { background: #744210; color: #faf089; }
        .severity-low { background: #22543d; color: #9ae6b4; }

        .risk-critical { background: #742a2a; color: #feb2b2; }
        .risk-high { background: #7b341e; color: #fbd38d; }
        .risk-medium { background: #744210; color: #faf089; }
        .risk-low { background: #22543d; color: #9ae6b4; }
        .risk-unknown { background: #2d3748; color: #cbd5e0; }

        .vuln-item, .rec-item {
            padding: 1rem;
            border-left: 4px solid;
            margin-bottom: 1rem;
            background: rgba(0,0,0,0.2);
            border-radius: 0 8px 8px 0;
        }

        .vuln-critical { border-color: var(--color-bad); }
        .vuln-high { border-color: #ed8936; }
        .vuln-medium { border-color: #ecc94b; }
        .vuln-low { border-color: var(--color-good); }

        .vuln-title, .rec-title {
            font-weight: bold;
            margin-bottom: 0.5rem;
        }

        .vuln-desc, .rec-desc {
            color: var(--color-text-dim);
            font-size: 0.9rem;
        }

        .vuln-remedy {
            margin-top: 0.5rem;
            padding: 0.5rem;
            background: rgba(102, 126, 234, 0.1);
            border-radius: 4px;
            font-size: 0.85rem;
        }

        .quantum-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }

        .quantum-metric {
            padding: 1rem;
            background: rgba(159, 122, 234, 0.1);
            border-radius: 8px;
            border: 1px solid rgba(159, 122, 234, 0.3);
        }

        .quantum-metric-label {
            font-size: 0.8rem;
            text-transform: uppercase;
            color: var(--color-text-dim);
        }

        .quantum-metric-value {
            font-size: 1.1rem;
            font-weight: bold;
            margin-top: 0.25rem;
        }

        .pqc-status {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }

        .pqc-item {
            flex: 1;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }

        .pqc-ready { background: rgba(72, 187, 120, 0.1); border: 1px solid var(--color-good); }
        .pqc-not-ready { background: rgba(245, 101, 101, 0.1); border: 1px solid var(--color-bad); }

        footer {
            text-align: center;
            padding: 2rem;
            color: var(--color-text-dim);
            font-size: 0.9rem;
        }

        footer a {
            color: var(--color-accent);
            text-decoration: none;
        }

        @media print {
            body { background: white; color: black; }
            .container { max-width: 100%; }
            section { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">QRAMM TLS Analyzer</div>
            <h1>Security Assessment Report</h1>
            <div class="target-info">
                <strong>Target:</strong> {{.Target}}
                {{if .IP}}({{.IP}}){{end}}<br>
                <strong>Scanned:</strong> {{formatTime .Timestamp}} |
                <strong>Duration:</strong> {{.Duration}}
            </div>
        </header>

        <div class="grades">
            <div class="grade-box {{gradeClass .Grade.Letter}}">
                <div class="grade-label">TLS Security</div>
                <div class="grade-letter">{{.Grade.Letter}}</div>
                <div class="grade-score">{{.Grade.Score}}/100</div>
            </div>
            <div class="grade-box quantum-grade">
                <div class="grade-label">Quantum Readiness</div>
                <div class="grade-letter">{{.Grade.QuantumGrade}}</div>
                {{if .QuantumRisk.Assessed}}
                <div class="grade-score">{{.QuantumRisk.Score}}/100</div>
                {{else}}
                <div class="grade-score">not assessed</div>
                {{end}}
            </div>
        </div>

        <section>
            <h2>Score Breakdown</h2>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Score</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Grade.Factors}}
                    <tr>
                        <td>{{.Category}}</td>
                        <td>{{progressBar .Score .MaxScore}}</td>
                        <td>{{.Details}}</td>
                    </tr>
                    {{end}}
                    <tr>
                        <td><strong>Dimension subtotal</strong></td>
                        <td><strong>{{.Grade.DimensionScore}}/100</strong></td>
                        <td>{{.Grade.DimensionPoints}} of {{.Grade.DimensionMaxPoints}} available points</td>
                    </tr>
                    <tr>
                        <td><strong>Vulnerability penalty</strong></td>
                        {{if not .Grade.VulnerabilitiesAssessed}}
                        <td><strong>not measured</strong></td>
                        <td>Vulnerability checks were skipped, so the score below is an upper bound and is not comparable with a full scan.</td>
                        {{else if .Grade.VulnerabilityPenalty}}
                        <td><strong>-{{.Grade.VulnerabilityPenalty}}</strong></td>
                        <td>{{describePenalties .Grade.Penalties}}</td>
                        {{else}}
                        <td><strong>none</strong></td>
                        <td>No vulnerability findings deducted points.</td>
                        {{end}}
                    </tr>
                    <tr>
                        <td><strong>TLS Security score</strong></td>
                        <td><strong>{{.Grade.Score}}/100</strong></td>
                        <td>{{if .Grade.PenaltyFloored}}The penalty exceeded the subtotal, so the score is held at 0.{{end}}</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section>
            <h2>Protocol Support</h2>
            <table>
                <thead>
                    <tr>
                        <th>Version</th>
                        <th>Status</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Protocols}}
                    <tr>
                        <td>{{.Version}}</td>
                        <td>{{protocolIcon .}}</td>
                        <td>
                            {{if .Preferred}}<span class="badge" style="background:#2d3748">Preferred</span>{{end}}
                            {{if and .Supported (isDeprecatedProtocol .Version)}}
                            <span class="badge severity-medium">Deprecated</span>
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </section>

        {{if .QuantumRisk.Assessed}}
        <section>
            <h2 class="quantum">Quantum Risk Assessment</h2>
            <div class="quantum-details">
                <div class="quantum-metric">
                    <div class="quantum-metric-label">Risk Level</div>
                    <div class="quantum-metric-value">
                        <span class="badge {{riskClass .QuantumRisk.Level}}">{{.QuantumRisk.Level}}</span>
                    </div>
                </div>
                <div class="quantum-metric">
                    <div class="quantum-metric-label">Key Exchange Risk</div>
                    <div class="quantum-metric-value">{{.QuantumRisk.KeyExchangeRisk}}</div>
                </div>
                <div class="quantum-metric">
                    <div class="quantum-metric-label">Certificate Risk</div>
                    <div class="quantum-metric-value">{{.QuantumRisk.CertificateRisk}}</div>
                </div>
                <div class="quantum-metric">
                    <div class="quantum-metric-label">HNDL Attack Risk</div>
                    <div class="quantum-metric-value">{{.QuantumRisk.HNDLRisk}}</div>
                </div>
            </div>

            <div class="pqc-status">
                <div class="pqc-item {{if .QuantumRisk.HybridPQCReady}}pqc-ready{{else}}pqc-not-ready{{end}}">
                    {{if .QuantumRisk.HybridPQCReady}}✓{{else}}✗{{end}} Hybrid PQC Key Exchange
                </div>
                <div class="pqc-item {{if .QuantumRisk.FullPQCReady}}pqc-ready{{else}}pqc-not-ready{{end}}">
                    {{if .QuantumRisk.FullPQCReady}}✓{{else}}✗{{end}} Full PQC Support
                </div>
            </div>

            <div class="quantum-metric" style="margin-top: 1rem;">
                <div class="quantum-metric-label">Recommended Action</div>
                <div class="quantum-metric-value">{{.QuantumRisk.TimeToAction}}</div>
            </div>
        </section>
        {{else}}
        <section>
            <h2 class="quantum">Quantum Risk Assessment</h2>
            <p>This scan did not assess quantum readiness, so this report says nothing
            about it. The section was previously drawn from a zero-valued assessment,
            which showed an empty risk level styled as low risk and a score of 0 out of
            100. Re-run without --skip-quantum to measure it.</p>
        </section>
        {{end}}

        {{if .Vulnerabilities}}
        <section>
            <h2>Vulnerabilities ({{len .Vulnerabilities}})</h2>
            {{range .Vulnerabilities}}
            <div class="vuln-item vuln-{{severityClass .Severity}}">
                <div class="vuln-title">
                    <span class="badge {{severityClass .Severity}}">{{.Severity}}</span>
                    {{.Name}}
                </div>
                <div class="vuln-desc">{{.Description}}</div>
                <div class="vuln-remedy">
                    <strong>Remediation:</strong> {{.Remediation}}
                </div>
            </div>
            {{end}}
        </section>
        {{end}}

        {{if .Recommendations}}
        <section>
            <h2>Recommendations</h2>
            {{range .Recommendations}}
            <div class="rec-item" style="border-color: var(--color-accent);">
                <div class="rec-title">#{{.Priority}} {{.Title}}</div>
                <div class="rec-desc">{{.Description}}</div>
                <div style="margin-top: 0.5rem; font-size: 0.85rem;">
                    <strong>Impact:</strong> {{.Impact}} |
                    <strong>Effort:</strong> {{.Effort}}
                </div>
            </div>
            {{end}}
        </section>
        {{end}}

        <footer>
            Generated by <a href="https://qramm.org">QRAMM TLS Analyzer</a> v{{.ScannerVersion}}<br>
            Part of the <a href="https://csnp.org">CSNP</a> Quantum Readiness Toolkit
        </footer>
    </div>
</body>
</html>`
