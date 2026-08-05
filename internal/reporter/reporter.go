// Package reporter provides output formatting for scan results.
package reporter

import (
	"io"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Reporter defines the interface for output formatters.
type Reporter interface {
	// Report writes the scan result to the writer.
	Report(w io.Writer, result *types.ScanResult) error

	// Format returns the format name.
	Format() string
}

// Format represents supported output formats.
type Format string

const (
	FormatJSON  Format = "json"
	FormatText  Format = "text"
	FormatSARIF Format = "sarif"
	FormatCBOM  Format = "cbom"
	FormatHTML  Format = "html"
)

// New creates a new reporter for the given format.
func New(format Format) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{}
	case FormatText:
		return &TextReporter{}
	case FormatSARIF:
		return &SARIFReporter{}
	case FormatCBOM:
		return &CBOMReporter{}
	case FormatHTML:
		return &HTMLReporter{IncludeCSS: true}
	default:
		return &TextReporter{}
	}
}

// targetWasNeverReached reports whether a result describes a target that
// produced no measurements.
//
// It exists so the classification is made in ONE place that every renderer
// consults, rather than in whichever renderer somebody remembered. That is not
// hypothetical: 0.3.0 fixed this for the single-target path, 0.4.0 fixed it for
// the batch text path and said in its CHANGELOG that batch mode no longer grades
// hosts it never reached, and that was true of one renderer of four. HTML
// rendered an empty grade letter, 0/100, a full breakdown of zeros and a red
// grade-f class; SARIF emitted a valid run reporting a successful invocation
// with no results; CBOM emitted an inventory listing no cryptography, for a host
// nothing had ever connected to. A user who passes --format html is not reading
// the text report.
//
// The decision is taken on the RAW result. The text renderer scrubs its copy
// before printing, and scrubbing collapses control characters and trims, so an
// Error consisting only of them scrubs to empty; deciding on the copy would send
// a target that was never reached down the fully-graded path, which is the
// inverse of the defect this prevents, introduced by the scrubbing that fixed a
// different one.
func targetWasNeverReached(result *types.ScanResult) bool {
	return result != nil && result.Error != ""
}

// ValidFormats returns all valid format strings.
func ValidFormats() []string {
	return []string{
		string(FormatJSON),
		string(FormatText),
		string(FormatSARIF),
		string(FormatCBOM),
		string(FormatHTML),
	}
}
