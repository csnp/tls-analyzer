package reporter

import (
	"fmt"
	"strings"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The certificate verdicts below, and negotiatedLabel, are worded once and
// rendered by both the text report and the HTML page, the same way
// describePenalties is. Two renderers that each carry their own copy of a
// verdict drift apart, and the reader of one format is then told something the
// other format does not say. The HTML page carried none of these until it was
// given the sections the text report has, so each one was written down here
// rather than copied into the template.
//
// The policy status and the milestone legend and marks below are rendered by
// both the text report and the HTML page, and the policy status words by SARIF
// and CBOM. The text report used to word its own policy status and draw its
// own milestone marks, and headed an evaluation that skipped rules COMPLIANT
// with a pass mark while the page said compliance was not established. The
// CNSA 2.0 algorithm tones are still the HTML page's alone.

// tone is what a verdict means, not what colour it is. Each renderer maps it to
// its own palette.
//
// The zero value is toneUnknown on purpose: a verdict nobody classified is not
// a good one.
type tone int

const (
	toneUnknown tone = iota
	toneGood
	toneWarn
	toneBad
	toneInfo
	toneDim
)

// mark is a verdict as a glyph and its words. Glyph is empty when the verdict
// has no symbol of its own, which is how an unrecognised status is shown: as
// its plain word, never borrowing the symbol for "met".
//
// The two certificate warnings below are drawn as "!", where they were U+26A0
// WARNING SIGN, which has the Unicode Emoji property. The protocol list and the
// HTML protocol icon draw the same "!" for a supported deprecated protocol.
type mark struct {
	Glyph string
	Label string
	Tone  tone
}

// String renders the mark as the text report prints it.
func (m mark) String() string {
	if m.Glyph == "" {
		return m.Label
	}
	return m.Glyph + " " + m.Label
}

// negotiatedLabel marks the suite or group this scan's own connection used. It
// is this scanner's client preference, not the server's, which the scan
// coverage notes explain.
const negotiatedLabel = "negotiated by this scan"

// certificateHeadline is the one verdict a certificate is headed with.
//
// A certificate a client would refuse must not be headed "Valid": the name and
// chain checks are part of that verdict, not a footnote to it.
func certificateHeadline(cert *types.Certificate) mark {
	switch {
	case cert.Expired:
		return mark{"✗", "EXPIRED", toneBad}
	case cert.NotYetValid:
		return mark{"✗", "NOT YET VALID", toneBad}
	case cert.NameMatch == types.CheckFailed:
		return mark{"✗", "NOT VALID FOR THIS NAME", toneBad}
	case cert.ChainTrust == types.CheckFailed:
		return mark{"✗", "NOT TRUSTED", toneBad}
	case cert.DaysUntilExpiry < 30:
		return mark{"!", fmt.Sprintf("Expiring in %d days", cert.DaysUntilExpiry), toneWarn}
	}
	return mark{"✓", "Valid", toneGood}
}

// certificateCheck renders one certificate check in its own right, so that
// "passed", "failed" and "did not run" are three visibly different answers.
func certificateCheck(result types.CheckResult, passed, failReason, notRun string) mark {
	switch result {
	case types.CheckPassed:
		return mark{"✓", passed, toneGood}
	case types.CheckFailed:
		if failReason == "" {
			failReason = "failed"
		}
		return mark{"✗", failReason, toneBad}
	}
	return mark{"?", notRun, toneWarn}
}

// nameCheck is the verdict on whether the certificate is valid for the name
// that was asked of the server.
func nameCheck(cert *types.Certificate) mark {
	return certificateCheck(cert.NameMatch,
		"valid for "+cert.RequestedName,
		cert.NameMismatchReason,
		"not checked against any name")
}

// chainCheck is the verdict on whether the presented chain builds to a root
// the scanning host trusts.
func chainCheck(cert *types.Certificate) mark {
	return certificateCheck(cert.ChainTrust,
		"chains to a root this host trusts",
		cert.ChainTrustReason,
		"not verified")
}

// selfSignedMark flags a certificate that is signed by its own key.
var selfSignedMark = mark{"!", "Self-signed certificate", toneWarn}

// certificateQuantum is whether the certificate's own signature scheme
// survives a quantum attack.
func certificateQuantum(cert *types.Certificate) mark {
	if cert.QuantumSafe {
		return mark{"✓", "Quantum Safe", toneGood}
	}
	return mark{"✗", "Quantum Vulnerable", toneBad}
}

// Policy status words, as the machine-readable formats carry them.
const (
	policyStatusCompliant      = "compliant"
	policyStatusNonCompliant   = "non-compliant"
	policyStatusNotEstablished = "compliance not established"
)

// policyStatus is the headline verdict of a policy evaluation as the text
// report and the HTML page show it.
//
// An evaluation that skipped rules and found no violation has not established
// compliance, only that the part of the policy that ran was satisfied, so
// policyStatus never heads it COMPLIANT and never gives it a pass mark. A
// violation found before a rule was skipped is still a violation, so that case
// is NON-COMPLIANT and policyIncompleteNote says the rest was not established.
func policyStatus(pr *types.PolicyResult) mark {
	switch {
	case !pr.Compliant:
		return mark{"✗", "NON-COMPLIANT", toneBad}
	case !pr.Complete:
		return mark{"?", "COMPLIANCE NOT ESTABLISHED", toneWarn}
	}
	return mark{"✓", "COMPLIANT", toneGood}
}

// policyStatusWord is policyStatus in the lower-case form SARIF and CBOM carry.
func policyStatusWord(pr *types.PolicyResult) string {
	switch {
	case !pr.Compliant:
		return policyStatusNonCompliant
	case !pr.Complete:
		return policyStatusNotEstablished
	}
	return policyStatusCompliant
}

// policyIncompleteNote explains an evaluation that skipped rules, and is empty
// for a complete one. The score is computed by deducting from 100, so a rule
// that was not evaluated can only have raised it.
func policyIncompleteNote(pr *types.PolicyResult) string {
	if pr.Complete {
		return ""
	}
	switch n := len(pr.SkippedRules); n {
	case 0:
		return "Compliance not established: this evaluation is not marked complete, " +
			"so it may cover only part of the policy."
	case 1:
		return "Compliance not established: 1 rule was not evaluated, so this verdict " +
			"covers only part of the policy and its score is not comparable with a " +
			"full evaluation."
	default:
		return fmt.Sprintf("Compliance not established: %d rules were not evaluated, "+
			"so this verdict covers only part of the policy and its score is not "+
			"comparable with a full evaluation.", n)
	}
}

// skippedRuleNames lists the rules an evaluation did not run, always as a list.
func skippedRuleNames(pr *types.PolicyResult) []string {
	names := make([]string, 0, len(pr.SkippedRules))
	for _, s := range pr.SkippedRules {
		names = append(names, s.Rule)
	}
	return names
}

// describeSkippedRules names each skipped rule with its reason, for the formats
// that carry the explanation as one line of text.
func describeSkippedRules(pr *types.PolicyResult) string {
	parts := make([]string, 0, len(pr.SkippedRules))
	for _, s := range pr.SkippedRules {
		parts = append(parts, s.Rule+" ("+s.Reason+")")
	}
	return strings.Join(parts, "; ")
}

// milestoneStatus is one CNSA 2.0 milestone status this report knows how to
// draw, with the words its legend gives it.
type milestoneStatus struct {
	Status string
	Mark   mark
}

// milestoneStatuses is the legend, in the order it is printed. A status that
// is not listed here has no symbol: milestoneMark shows it as its plain word.
// A milestone not yet required is marked "-", where it was U+2014 EM DASH.
var milestoneStatuses = []milestoneStatus{
	{"compliant", mark{"✓", "met", toneGood}},
	{"partial", mark{"◐", "partial", toneWarn}},
	{"in-progress", mark{"○", "in progress", toneInfo}},
	{"non-compliant", mark{"✗", "not met", toneBad}},
	{"not-applicable", mark{"-", "not yet required", toneDim}},
}

// milestoneMark is the symbol and words for a milestone status.
//
// A status this table does not list is drawn as its own word with no symbol
// and no colour, never as met. Defaulting to the symbol for "met" is how a
// status added later, such as one meaning the scan could not tell, would be
// shown as satisfied.
func milestoneMark(status string) mark {
	for _, s := range milestoneStatuses {
		if s.Status == status {
			return s.Mark
		}
	}
	if status == "" {
		status = "status not recorded"
	}
	return mark{"", status, toneUnknown}
}

// milestoneMarkAt is milestoneMark for a milestone of a timeline assessed at
// assessed. A milestone that is not met and whose deadline is not after the
// assessment date is also said to be past its deadline.
//
// The analyzer marks the Preparation Phase in progress whenever a scan runs, so
// on 2026-10-18 the timeline printed "○ in progress: Preparation Phase
// (2025-12-31)" under "Current Phase: New NSS Systems", with nothing to say that
// its deadline had passed. The deadline is compared with the assessment date the
// timeline carries, the date its current phase was worked out from, so a saved
// result reads the same later. A timeline or a milestone without a date says
// nothing about deadlines.
func milestoneMarkAt(m types.CNSA2Milestone, assessed time.Time) mark {
	mk := milestoneMark(m.Status)
	if m.Status != "compliant" && !assessed.IsZero() && !m.Deadline.IsZero() &&
		!assessed.Before(m.Deadline) {
		mk.Label += ", deadline passed"
	}
	return mk
}

// cnsa2FindingTone is how an algorithm's CNSA 2.0 status is coloured. A status
// it does not know is unknown, never approved.
func cnsa2FindingTone(status string) tone {
	switch status {
	case "approved":
		return toneGood
	case "transitional":
		return toneWarn
	case "deprecated", "prohibited":
		return toneBad
	}
	return toneUnknown
}

// cnsa2FindingNeedsReplacement reports whether a finding's replacement is
// advice to act on rather than a note.
func cnsa2FindingNeedsReplacement(f types.CNSA2Finding) bool {
	return f.Replacement != "" && (f.Status == "deprecated" || f.Status == "prohibited")
}

// cnsa2FindingRow is one line of the CNSA 2.0 algorithm status list: a finding,
// and how many findings read the same as it.
type cnsa2FindingRow struct {
	types.CNSA2Finding
	Count int
}

// cnsa2FindingRows folds the findings that read the same into one row each, in
// the order each first appears, for the text report and the HTML page.
//
// The analyzer makes one symmetric finding per cipher suite, so a server with
// 17 AES suites printed "[approved    ] symmetric: AES" 8 times and
// "[transitional] symmetric: AES" 9 times, naming no suite. A line shows a
// finding's status, category and algorithm, and its replacement when that is
// advice to act on, so those decide which findings read the same.
func cnsa2FindingRows(findings []types.CNSA2Finding) []cnsa2FindingRow {
	type line struct{ status, category, algorithm, replacement string }

	rows := make([]cnsa2FindingRow, 0, len(findings))
	index := make(map[line]int, len(findings))
	for _, f := range findings {
		key := line{status: f.Status, category: f.Category, algorithm: f.Algorithm}
		if cnsa2FindingNeedsReplacement(f) {
			key.replacement = f.Replacement
		}
		if i, ok := index[key]; ok {
			rows[i].Count++
			continue
		}
		index[key] = len(rows)
		rows = append(rows, cnsa2FindingRow{CNSA2Finding: f, Count: 1})
	}
	return rows
}

// cnsa2FindingCount says how many findings a row stands for, and is empty for
// a row of one. The analyzer makes a symmetric finding for each cipher suite,
// so those are counted as cipher suites.
func cnsa2FindingCount(row cnsa2FindingRow) string {
	switch {
	case row.Count < 2:
		return ""
	case row.Category == "symmetric":
		return fmt.Sprintf("%d cipher suites", row.Count)
	}
	return fmt.Sprintf("%d findings", row.Count)
}
