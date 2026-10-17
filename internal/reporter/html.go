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
	// A target that could not be reached has no measurements, so it gets no
	// grade. This renderer had no such branch and the template rendered neither
	// .Error nor .ScanWarnings, so an unreachable host produced an empty grade
	// letter, "0/100", a full breakdown of zeros and a red grade-f class, with
	// nothing anywhere on the page saying the host was never contacted. A saved
	// HTML report is the format most likely to be sent to somebody who did not
	// run the scan, which is the worst place for a fabricated grade.
	if targetWasNeverReached(result) {
		return r.reportUnreached(w, result)
	}

	// Scrubbed at the door, whole result, exactly as reportUnreached does it,
	// and decided after the unreached check above, which reads the raw result.
	//
	// html/template escapes markup and does NOT escape control characters, so a
	// saved HTML report could carry a raw cursor sequence that steers a terminal
	// the moment somebody cats, greps or pages the file. Nothing reached that gap
	// only because this page drew no subject, issuer or SAN, which are the
	// server's own choice of text. It draws them now, so the scrub comes first,
	// and a field added to the page later is covered without anyone remembering.
	result = sanitizedForText(result)

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
		// The certificate verdict words and negotiatedLabel below are shared
		// the same way, and so are policyStatus and the milestone legend and
		// marks. policyIncompleteNote and the two CNSA 2.0 finding helpers
		// live in verdict_marks.go too, but only this page renders them.
		"toneClass":                    toneClass,
		"formatDate":                   formatDate,
		"certificateHeadline":          certificateHeadline,
		"nameCheck":                    nameCheck,
		"chainCheck":                   chainCheck,
		"certificateQuantum":           certificateQuantum,
		"selfSignedMark":               func() mark { return selfSignedMark },
		"negotiatedLabel":              func() string { return negotiatedLabel },
		"policyStatus":                 policyStatus,
		"policyIncompleteNote":         policyIncompleteNote,
		"milestoneMark":                milestoneMark,
		"milestoneStatuses":            func() []milestoneStatus { return milestoneStatuses },
		"cnsa2FindingTone":             cnsa2FindingTone,
		"cnsa2FindingNeedsReplacement": cnsa2FindingNeedsReplacement,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl.Execute(w, result)
}

// reportUnreached renders the page for a target that produced no measurements.
//
// It is a separate template rather than a conditional inside the report
// template, so there is no path on which a grade box, a score breakdown or a
// findings table can be reached for a host nothing connected to. A guard added
// inside the main template would have to be repeated at each of those sections
// and would silently stop covering a section added later.
func (r *HTMLReporter) reportUnreached(w io.Writer, result *types.ScanResult) error {
	// Scrubbed at the door, whole result, the same way the text renderer and the
	// graded page do it.
	//
	// html/template escapes markup and does NOT escape control characters, so a
	// saved HTML report can carry a raw cursor-up sequence that steers a terminal
	// the moment somebody cats, greps or pages the file. sanitizedForText is
	// named for the renderer it was written for and is not text-specific; it
	// walks the type rather than a list of fields, so this page needs no
	// per-field decisions and a field added to it later is covered without anyone
	// remembering.
	result = sanitizedForText(result)

	tmpl, err := template.New("unreached").Funcs(template.FuncMap{
		"formatTime": formatTime,
	}).Parse(htmlUnreachedTemplate)
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

func formatDate(t time.Time) string {
	return t.Format("2006-01-02")
}

// toneClass is the stylesheet class for a verdict's tone. An unknown tone gets
// a neutral class of its own, never the class for a good outcome.
func toneClass(t tone) string {
	switch t {
	case toneGood:
		return "status-good"
	case toneWarn:
		return "status-warn"
	case toneBad:
		return "status-bad"
	case toneInfo:
		return "status-info"
	case toneDim:
		return "status-dim"
	}
	return "status-unknown"
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

        h3 { font-size: 1rem; margin: 1.25rem 0 0.5rem; }

        .status-info { color: var(--color-accent); }
        .status-dim { color: var(--color-text-dim); }
        .status-unknown { color: var(--color-text); }
        .verdict { font-weight: bold; }

        .facts th {
            width: 12rem;
            vertical-align: top;
            text-transform: none;
            font-size: 0.85rem;
        }
        .facts td { word-break: break-word; }

        .note { color: var(--color-text-dim); font-size: 0.9rem; margin-top: 0.75rem; }

        .plain-list { list-style: none; }
        .plain-list > li { padding: 0.35rem 0; }
        .plain-list ul { margin: 0.25rem 0 0 1.75rem; color: var(--color-text-dim); }

        .finding-item {
            padding: 1rem;
            border-left: 4px solid var(--color-border);
            margin-bottom: 1rem;
            background: rgba(0,0,0,0.2);
            border-radius: 0 8px 8px 0;
            overflow-wrap: anywhere;
        }
        .finding-severity-critical, .finding-severity-high { border-color: var(--color-bad); }
        .finding-severity-medium { border-color: var(--color-warn); }
        .finding-severity-low, .finding-severity-info { border-color: var(--color-accent); }
        .finding-detail { color: var(--color-text-dim); font-size: 0.9rem; margin-top: 0.25rem; }

        .tag {
            display: inline-block;
            padding: 0.1rem 0.4rem;
            margin: 0.1rem 0.25rem 0.1rem 0;
            border-radius: 4px;
            font-size: 0.75rem;
            background: var(--color-border);
        }

        code {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 0.85rem;
            overflow-wrap: anywhere;
        }

        @media (max-width: 600px) {
            body { padding: 1rem; }
            .grades { flex-direction: column; gap: 1rem; }
            .facts th { width: auto; }
            .facts th, .facts td, .stack-table td { display: block; border-bottom: none; padding: 0.25rem 0; }
            .facts tr, .stack-table tr { display: block; border-bottom: 1px solid var(--color-border); padding: 0.5rem 0; }
            .stack-table thead { display: none; }
            .stack-table td:empty { display: none; }
            .stack-table td::before {
                content: attr(data-label) ": ";
                color: var(--color-text-dim);
                font-size: 0.8rem;
            }
        }

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

        <section id="score-breakdown">
            <h2>Score Breakdown</h2>
            <table class="stack-table">
                <thead>
                    <tr>
                        <th scope="col">Category</th>
                        <th scope="col">Score</th>
                        <th scope="col">Details</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Grade.Factors}}
                    <tr>
                        <td data-label="Category">{{.Category}}</td>
                        <td data-label="Score">{{progressBar .Score .MaxScore}}</td>
                        <td data-label="Details">{{.Details}}</td>
                    </tr>
                    {{end}}
                    <tr>
                        <td data-label="Category"><strong>Dimension subtotal</strong></td>
                        <td data-label="Score"><strong>{{.Grade.DimensionScore}}/100</strong></td>
                        <td data-label="Details">{{.Grade.DimensionPoints}} of {{.Grade.DimensionMaxPoints}} available points</td>
                    </tr>
                    <tr>
                        <td data-label="Category"><strong>Vulnerability penalty</strong></td>
                        {{if not .Grade.VulnerabilitiesAssessed}}
                        <td data-label="Score"><strong>not measured</strong></td>
                        <td data-label="Details">Vulnerability checks were skipped, so the score below is an upper bound and is not comparable with a full scan.</td>
                        {{else if .Grade.VulnerabilityPenalty}}
                        <td data-label="Score"><strong>-{{.Grade.VulnerabilityPenalty}}</strong></td>
                        <td data-label="Details">{{describePenalties .Grade.Penalties}}</td>
                        {{else}}
                        <td data-label="Score"><strong>none</strong></td>
                        <td data-label="Details">No vulnerability findings deducted points.</td>
                        {{end}}
                    </tr>
                    <tr>
                        <td data-label="Category"><strong>TLS Security score</strong></td>
                        <td data-label="Score"><strong>{{.Grade.Score}}/100</strong></td>
                        <td data-label="Details">{{if .Grade.PenaltyFloored}}The penalty exceeded the subtotal, so the score is held at 0.{{end}}</td>
                    </tr>
                </tbody>
            </table>
        </section>

        {{with .PolicyResult}}
        <section id="policy">
            <h2>Policy evaluation</h2>
            <table class="facts">
                <tbody>
                    <tr><th scope="row">Policy</th><td>{{.PolicyName}}</td></tr>
                    <tr><th scope="row">Status</th><td>{{template "mark" (policyStatus .)}}</td></tr>
                    <tr><th scope="row">Score</th><td>{{.Score}}/100{{if not .Complete}} <span class="status-warn">(not comparable with a full evaluation)</span>{{end}}</td></tr>
                    {{if .Scope}}<tr><th scope="row">Scope</th><td>{{.Scope}}</td></tr>{{end}}
                </tbody>
            </table>
            {{with policyIncompleteNote .}}<p class="note status-warn">{{.}}</p>{{end}}

            {{if .Violations}}
            <h3>Violations ({{len .Violations}})</h3>
            {{range .Violations}}
            <div class="finding-item finding-{{severityClass .Severity}}">
                <div class="vuln-title"><span class="badge {{severityClass .Severity}}">{{.Severity}}</span> {{.Description}}</div>
                <div class="finding-detail">Rule: <code>{{.Rule}}</code></div>
                <div class="finding-detail">Expected: {{.Expected}} | Actual: {{.Actual}}</div>
                {{if .Remediation}}<div class="vuln-remedy"><strong>Fix:</strong> {{.Remediation}}</div>{{end}}
            </div>
            {{end}}
            {{end}}

            {{if .Warnings}}
            <h3>Warnings ({{len .Warnings}})</h3>
            {{range .Warnings}}
            <div class="finding-item finding-{{severityClass .Severity}}">
                <div class="vuln-title"><span class="badge {{severityClass .Severity}}">{{.Severity}}</span> {{.Description}}</div>
                <div class="finding-detail">Rule: <code>{{.Rule}}</code></div>
                {{if .Remediation}}<div class="vuln-remedy"><strong>Fix:</strong> {{.Remediation}}</div>{{end}}
            </div>
            {{end}}
            {{end}}

            {{if .SkippedRules}}
            <h3>Not evaluated ({{len .SkippedRules}})</h3>
            <p class="note">These rules were neither passed nor failed, because this scan did not measure what they read.</p>
            <ul class="plain-list">
                {{range .SkippedRules}}<li><code>{{.Rule}}</code>: {{.Reason}}</li>{{end}}
            </ul>
            {{end}}
        </section>
        {{end}}

        {{with .CNSA2Timeline}}
        <section id="cnsa2-timeline">
            <h2 class="quantum">CNSA 2.0 compliance timeline</h2>
            <table class="facts">
                <tbody>
                    <tr><th scope="row">Current phase</th><td>{{.CurrentPhase}}</td></tr>
                    <tr><th scope="row">Timeline score</th><td>{{.TimelineScore}}/100</td></tr>
                    <tr><th scope="row">Days to next deadline</th><td>{{.DaysToNextDeadline}}</td></tr>
                    <tr><th scope="row">Next action</th><td>{{.NextAction}}</td></tr>
                    {{if .Scope}}<tr><th scope="row">Scope</th><td>{{.Scope}}</td></tr>{{end}}
                </tbody>
            </table>

            <h3>Milestones</h3>
            <p class="note">Legend: {{range $i, $s := milestoneStatuses}}{{if $i}}, {{end}}{{template "mark" $s.Mark}}{{end}}</p>
            <ul class="plain-list">
                {{range .Milestones}}
                <li>{{template "mark" (milestoneMark .Status)}}: {{.Name}} ({{formatDate .Deadline}}){{if .Gap}}
                    <ul>{{range .Gap}}<li>{{.}}</li>{{end}}</ul>{{end}}
                </li>
                {{end}}
            </ul>

            {{if .Findings}}
            <h3>Algorithm status</h3>
            <ul class="plain-list">
                {{range .Findings}}
                <li><span class="verdict {{toneClass (cnsa2FindingTone .Status)}}">{{.Status}}</span>: {{.Category}}, {{.Algorithm}}{{if cnsa2FindingNeedsReplacement .}}. Replace with {{.Replacement}}{{end}}</li>
                {{end}}
            </ul>
            {{end}}
        </section>
        {{end}}

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

        <section id="cipher-suites">
            <h2>Cipher suites and key exchange</h2>
            {{if .CipherSuites}}
            <table class="stack-table">
                <thead>
                    <tr>
                        <th scope="col">Status</th>
                        <th scope="col">Cipher suite</th>
                        <th scope="col">Protocol</th>
                        <th scope="col">Key size</th>
                        <th scope="col">Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .CipherSuites}}
                    <tr>
                        <td data-label="Status">{{if .Deprecated}}<span class="status-icon status-bad" aria-hidden="true">✗</span> deprecated{{else}}<span class="status-icon status-good" aria-hidden="true">✓</span> accepted{{end}}</td>
                        <td data-label="Cipher suite"><code>{{.Name}}</code>{{if .Deprecated}}<div class="finding-detail">{{.DeprecatedReason}}</div>{{end}}</td>
                        <td data-label="Protocol">{{.Protocol}}</td>
                        <td data-label="Key size">{{.Bits}}-bit</td>
                        <td data-label="Notes">{{if or .ForwardSecrecy .QuantumSafe .Negotiated}}{{if .ForwardSecrecy}}<span class="tag">forward secrecy</span>{{end}}{{if .QuantumSafe}}<span class="tag">post-quantum</span>{{end}}{{if .Negotiated}}<span class="tag">{{negotiatedLabel}}</span>{{end}}{{else}}none{{end}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <p>No cipher information available.</p>
            {{end}}

            {{if .KeyExchanges}}
            <h3>Key exchange groups</h3>
            <table class="stack-table">
                <thead>
                    <tr>
                        <th scope="col">Group</th>
                        <th scope="col">Type</th>
                        <th scope="col">Post-quantum part</th>
                        <th scope="col">Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .KeyExchanges}}
                    <tr>
                        <td data-label="Group"><code>{{.Name}}</code></td>
                        <td data-label="Type">{{.Type}}</td>
                        <td data-label="Post-quantum part">{{if .PQCAlgorithm}}{{.PQCAlgorithm}}{{if .HybridClassical}} with {{.HybridClassical}}{{end}}{{else}}none{{end}}</td>
                        <td data-label="Notes">{{if or .QuantumSafe .Negotiated}}{{if .QuantumSafe}}<span class="tag">post-quantum</span>{{end}}{{if .Negotiated}}<span class="tag">{{negotiatedLabel}}</span>{{end}}{{else}}none{{end}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{end}}
        </section>

        {{with .Certificate}}
        <section id="certificate">
            <h2>Certificate</h2>
            <table class="facts">
                <tbody>
                    <tr><th scope="row">Status</th><td>{{template "mark" (certificateHeadline .)}}</td></tr>
                    <tr><th scope="row">Subject</th><td>{{.Subject}}</td></tr>
                    <tr><th scope="row">Issuer</th><td>{{.Issuer}}</td></tr>
                    <tr><th scope="row">Valid</th><td>{{formatDate .NotBefore}} to {{formatDate .NotAfter}}</td></tr>
                    <tr><th scope="row">Key</th><td>{{.PublicKeyAlgorithm}} {{.PublicKeyBits}}-bit</td></tr>
                    <tr><th scope="row">Signature</th><td>{{.SignatureAlgorithm}}</td></tr>
                    {{if .SANs}}<tr><th scope="row">Names (SANs)</th><td><ul class="plain-list">{{range .SANs}}<li><code>{{.}}</code></li>{{end}}</ul></td></tr>{{end}}
                    <tr><th scope="row">Name check</th><td>{{template "mark" (nameCheck .)}}</td></tr>
                    <tr><th scope="row">Chain trust</th><td>{{template "mark" (chainCheck .)}}</td></tr>
                    {{if .IsSelfSigned}}<tr><th scope="row">Self-signed</th><td>{{template "mark" selfSignedMark}}</td></tr>{{end}}
                    <tr><th scope="row">Quantum</th><td>{{template "mark" (certificateQuantum .)}}</td></tr>
                </tbody>
            </table>
        </section>
        {{end}}

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

        {{if .ScanWarnings}}
        <section id="scan-coverage">
            <h2>Scan coverage</h2>
            <p class="note">The limits on what this scan could observe. Anything outside them is not measured here, so it is not reported as passed.</p>
            <ul class="plain-list">
                {{range .ScanWarnings}}<li>{{.}}</li>{{end}}
            </ul>
        </section>
        {{end}}

        <footer>
            Generated by <a href="https://qramm.org">QRAMM TLS Analyzer</a> v{{.ScannerVersion}}<br>
            Part of the <a href="https://csnp.org">CSNP</a> Quantum Readiness Toolkit
        </footer>
    </div>
</body>
</html>
{{- define "mark"}}<span class="verdict {{toneClass .Tone}}">{{if .Glyph}}<span aria-hidden="true">{{.Glyph}}</span> {{end}}{{.Label}}</span>{{end -}}
`

// htmlUnreachedTemplate is the page for a target that produced no measurements.
//
// It states what happened and stops. There is deliberately no grade box, no
// score, no breakdown and no findings table anywhere in it, because the defect
// this exists for is a page that rendered all four from a zero-valued result.
const htmlUnreachedTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QRAMM TLS Analysis Report - {{.Target}} - not scanned</title>
    <style>
        :root {
            --color-bg: #0f1419;
            --color-card: #1a1f2e;
            --color-border: #2d3748;
            --color-text: #e2e8f0;
            --color-text-dim: #718096;
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

        h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }

        .target-info { color: var(--color-text-dim); font-size: 0.9rem; }

        section {
            background: var(--color-card);
            border: 1px solid var(--color-border);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        h2 {
            font-size: 1.15rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--color-border);
            color: var(--color-bad);
        }

        .reason {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 0.9rem;
            background: var(--color-bg);
            border: 1px solid var(--color-border);
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .note { color: var(--color-text-dim); margin-top: 1rem; font-size: 0.9rem; }

        ul { margin: 0.5rem 0 0 1.25rem; }

        footer {
            text-align: center;
            color: var(--color-text-dim);
            font-size: 0.85rem;
            padding-top: 1rem;
        }

        footer a { color: var(--color-quantum); }

        @media (max-width: 600px) {
            body { padding: 1rem; }
            header { padding: 1.25rem; }
            h1 { font-size: 1.35rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">QRAMM TLS Analyzer</div>
            <h1>Not scanned</h1>
            <div class="target-info">
                <strong>Target:</strong> {{.Target}}<br>
                <strong>Attempted:</strong> {{formatTime .Timestamp}}
            </div>
        </header>

        <section>
            <h2>This target produced no measurements</h2>
            <div class="reason">{{.Error}}</div>
            <p class="note">
                No grade is reported for this target, because nothing was measured.
                A grade here would describe a connection that never happened.
            </p>
        </section>

        {{if .ScanWarnings}}
        <section>
            <h2>Scan coverage</h2>
            <ul>
                {{range .ScanWarnings}}<li>{{.}}</li>{{end}}
            </ul>
        </section>
        {{end}}

        <footer>
            Generated by <a href="https://qramm.org">QRAMM TLS Analyzer</a> v{{.ScannerVersion}}<br>
            Part of the <a href="https://csnp.org">CSNP</a> Quantum Readiness Toolkit
        </footer>
    </div>
</body>
</html>`
