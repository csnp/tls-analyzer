package reporter

import (
	"reflect"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// sanitizedForText returns a copy of result with every string scrubbed of the
// control characters that let untrusted text forge the report.
//
// WHY A COPY OF THE WHOLE RESULT, RATHER THAN A CALL AT EACH PRINT SITE.
//
// Sanitising per print site was tried four times in one release and three of
// those attempts shipped incomplete. Each fix closed the fields a reviewer had
// named and left the next one open: policy name and description, then the rule
// values, then the findings block, then the target, the scan warnings and the
// scan error. The failure was never the sanitiser. It was that a print site is
// only protected if somebody remembered it, and the reviews kept finding the
// ones nobody had.
//
// The judgement that field X "cannot be hostile because production fills it from
// a constant" is the specific thing that keeps failing. It is usually true and
// occasionally wrong, and being occasionally wrong is what a forgery needs. It
// was wrong twice in the review that produced this file: the scan warnings were
// classed as tool prose when they interpolate --sni, and the grade factor detail
// was classed as never printed when it is printed and carries the requested
// name.
//
// So the renderer stops deciding. Everything it is handed is scrubbed once, at
// the door, and every print site below is safe whether or not its author thought
// about it. This is the shape the analyzer already uses for the policy verdict,
// where sanitising one layer up is what makes the unsanitised print sites in
// this file harmless.
//
// It is a COPY because the caller may render the same result again in another
// format, and JSON, SARIF and CBOM must keep the bytes the server actually sent.
// Their encoders escape control characters rather than executing them, so they
// are honest already, and an operator diffing JSON should see what was really
// presented. Only the text report is read by a terminal, and only the text
// report needs this.
//
// The ten per-print-site sanitize.ForReport calls text.go used to carry
// were removed when this was added, rather than kept as a second layer. They
// were unreachable as an independent defence: every print helper in that file is
// unexported and called only from Report, so nothing could reach one without
// passing through here first. Keeping them would have left ten call sites
// no test could distinguish from no call sites, which is the shape that just
// cost this release a review round, where a %q was documented as an independent
// defence and turned out to be silently carried by the sanitiser beside it.
//
// One defence, tested. A print site added later needs no call of its own.
func sanitizedForText(result *types.ScanResult) *types.ScanResult {
	if result == nil {
		return nil
	}
	clean := &types.ScanResult{}
	sanitizeInto(reflect.ValueOf(result).Elem(), reflect.ValueOf(clean).Elem())
	return clean
}

// sanitizeInto deep-copies src into dst, scrubbing every string on the way.
func sanitizeInto(src, dst reflect.Value) {
	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		dst.Set(reflect.New(src.Type().Elem()))
		sanitizeInto(src.Elem(), dst.Elem())

	case reflect.Struct:
		// A struct holding unexported fields cannot be rebuilt field by field, and
		// reflection cannot read them to try. time.Time is the one this type graph
		// contains, and it is copied whole.
		//
		// It is NOT true that it carries no string a report prints, which is what
		// this comment used to say. printHeader formats the timestamp with a MST
		// layout element, which prints the location's zone name, and a
		// time.FixedZone name is an arbitrary string this scrub does not reach. The
		// copy also shares the caller's *time.Location. Neither is reachable from a
		// scan, because the timestamp comes from time.Now() and a JSON round trip
		// carries a numeric offset rather than a name, so this is a bound on the
		// claim rather than a live hole: everything handed to the renderer is
		// scrubbed EXCEPT strings behind a struct reflection cannot rebuild.
		if hasUnexportedField(src.Type()) {
			dst.Set(src)
			return
		}
		for i := 0; i < src.NumField(); i++ {
			sanitizeInto(src.Field(i), dst.Field(i))
		}

	case reflect.Slice:
		if src.IsNil() {
			return
		}
		dst.Set(reflect.MakeSlice(src.Type(), src.Len(), src.Len()))
		for i := 0; i < src.Len(); i++ {
			sanitizeInto(src.Index(i), dst.Index(i))
		}

	case reflect.Array:
		// Fixed size, so dst is already the right shape. Handled explicitly
		// because the default arm copies verbatim, and an array of strings would
		// have been copied unscrubbed while looking covered.
		for i := 0; i < src.Len(); i++ {
			sanitizeInto(src.Index(i), dst.Index(i))
		}

	case reflect.Map:
		if src.IsNil() {
			return
		}
		out := reflect.MakeMapWithSize(src.Type(), src.Len())
		for _, k := range src.MapKeys() {
			key := reflect.New(src.Type().Key()).Elem()
			sanitizeInto(k, key)
			val := reflect.New(src.Type().Elem()).Elem()
			sanitizeInto(src.MapIndex(k), val)
			out.SetMapIndex(key, val)
		}
		dst.Set(out)

	case reflect.String:
		dst.SetString(sanitize.ForReport(src.String(), sanitize.MaxReportDetail))

	default:
		dst.Set(src)
	}
}

// hasUnexportedField reports whether t carries a field reflection cannot set.
func hasUnexportedField(t reflect.Type) bool {
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).PkgPath != "" {
			return true
		}
	}
	return false
}
