package reporter

import (
	"regexp"
	"strings"
	"testing"
)

// The Score Breakdown table was the one wide table on the page that did not
// stack its cells below 600px, so at a 375px viewport it measured 444px wide
// and the page scrolled sideways. The policy, timeline, cipher suite and
// certificate tables fit because they stack.

var tableCell = regexp.MustCompile(`<td[^>]*>`)

// TestHTMLScoreBreakdownStacksOnANarrowScreen requires the table to use the
// stacking class, and every cell to carry the label the stacked layout prints
// in place of the hidden column header.
func TestHTMLScoreBreakdownStacksOnANarrowScreen(t *testing.T) {
	page := render(t, &HTMLReporter{IncludeCSS: true}, fullResult())
	section := htmlSection(t, page, "score-breakdown")

	if !strings.Contains(section, `<table class="stack-table">`) {
		t.Errorf("the Score Breakdown table does not stack below 600px:\n%s", section)
	}
	cells := tableCell.FindAllString(section, -1)
	if len(cells) == 0 {
		t.Fatalf("the Score Breakdown section has no cells:\n%s", section)
	}
	for _, cell := range cells {
		if !strings.Contains(cell, `data-label="`) {
			t.Errorf("cell %s has no data-label, so the stacked layout shows it without "+
				"its column name", cell)
		}
	}

	// The control: the rule the class relies on is in the stylesheet.
	if !strings.Contains(page, ".stack-table td { display: block;") {
		t.Error("the stylesheet no longer stacks .stack-table cells, so the class does nothing")
	}
}
