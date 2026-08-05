package reporter

import (
	"io"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// JSONReporter outputs results in JSON format.
type JSONReporter struct {
	Compact bool
}

// Report writes the scan result as JSON.
//
// Through WriteJSON rather than a bare encoder, so the control characters
// encoding/json leaves raw are escaped. See WriteJSON for which and why.
func (r *JSONReporter) Report(w io.Writer, result *types.ScanResult) error {
	indent := "  "
	if r.Compact {
		indent = ""
	}
	return WriteJSON(w, result, indent)
}

// Format returns the format name.
func (r *JSONReporter) Format() string {
	return string(FormatJSON)
}
