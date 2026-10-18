package reporter

import (
	"errors"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// errDiskFull is what failingWriter returns for every write.
var errDiskFull = errors.New("no space left on device")

// failingWriter refuses every write, as a full disk does.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errDiskFull }

// TestEveryFormatReturnsAWriteError checks that a report that could not be
// written says so, in every format. The text report printed each line with an
// unchecked fmt.Fprintf and returned nil whatever the writer answered, so it was
// the one format whose caller could not tell that nothing was written.
func TestEveryFormatReturnsAWriteError(t *testing.T) {
	reporters := []Reporter{
		&TextReporter{NoColor: true},
		&JSONReporter{},
		&SARIFReporter{},
		&CBOMReporter{},
		&HTMLReporter{},
	}
	for _, rep := range reporters {
		for name, result := range map[string]*types.ScanResult{
			"scanned":     fullResult(),
			"not scanned": unreachedResult(),
		} {
			err := rep.Report(failingWriter{}, result)
			if !errors.Is(err, errDiskFull) {
				t.Errorf("%s, %s: Report returned %v for a writer that refused every write, want %v",
					rep.Format(), name, err, errDiskFull)
			}
		}
	}
}
