package reporter

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The forgery sweep claims a field added to types.ScanResult is covered the day
// it is added. That claim is only true for the kinds sanitizeInto actually
// scrubs and fillHostile actually fills, and those two have the SAME blind
// spots: sanitizeInto's default arm copies interface, chan and func values
// verbatim, and fillHostile has no case for them either. A field of one of those
// kinds would therefore be neither scrubbed nor swept, and every existing test
// would stay green while a hostile value reached the report raw.
//
// Rather than pretend the reflection walkers handle every kind Go has, this
// asserts that the type graph contains none of the kinds they cannot handle. A
// contributor who adds one gets a failure here, naming the field and saying what
// to do, instead of a silent hole discovered by the next adversarial review.
//
// This is the guard on the guard. The sweep already passed once while exercising
// three of its hundred and twenty-one payloads, so its coverage claims are worth
// asserting rather than believing.
func TestTheResultTypeGraphContainsNoKindTheScrubberCannotHandle(t *testing.T) {
	var problems []string
	seen := map[reflect.Type]bool{}
	walkType(reflect.TypeOf(types.ScanResult{}), "ScanResult", seen, &problems, 0)

	for _, p := range problems {
		t.Error(p)
	}
}

func walkType(t reflect.Type, path string, seen map[reflect.Type]bool, problems *[]string, depth int) {
	if depth > 20 {
		*problems = append(*problems, fmt.Sprintf(
			"%s: the type graph is deeper than 20 levels or is CYCLIC. sanitizeInto "+
				"recurses without a depth bound, so a cycle here is a stack overflow at "+
				"render time, not a recoverable panic", path))
		return
	}
	if seen[t] {
		return
	}
	seen[t] = true

	switch t.Kind() {
	case reflect.Interface:
		*problems = append(*problems, fmt.Sprintf(
			"%s is an interface. sanitizeInto's default arm copies it VERBATIM, so any "+
				"string inside reaches the report unscrubbed, and fillHostile has no case "+
				"for it so the forgery sweep will not notice. Give sanitizeInto and "+
				"fillHostile an Interface case before adding this field", path))

	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		*problems = append(*problems, fmt.Sprintf(
			"%s is a %s, which the deep copy cannot meaningfully duplicate", path, t.Kind()))

	case reflect.Struct:
		if t == reflect.TypeOf(time.Time{}) {
			// Copied whole because reflection cannot rebuild it. It does carry one
			// string a report can print, the location's zone name, which
			// sanitizedForText therefore does not reach. Recorded in the function's
			// own comment; not reachable from a scan, since the timestamp comes
			// from time.Now().
			return
		}
		if hasUnexportedField(t) {
			*problems = append(*problems, fmt.Sprintf(
				"%s is a struct with unexported fields. sanitizeInto copies such a struct "+
					"VERBATIM, because reflection cannot rebuild it field by field, so any "+
					"string it carries reaches the report unscrubbed. time.Time is the only "+
					"one this graph is allowed to contain", path))
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			walkType(f.Type, path+"."+f.Name, seen, problems, depth+1)
		}

	case reflect.Pointer, reflect.Slice, reflect.Array:
		walkType(t.Elem(), path+"[]", seen, problems, depth+1)

	case reflect.Map:
		walkType(t.Key(), path+"[key]", seen, problems, depth+1)
		walkType(t.Elem(), path+"[val]", seen, problems, depth+1)
	}
}

// TestTheTypeGraphGuardActuallyFires proves the guard above is not vacuous.
//
// A guard that reports no problems because its walker never reaches anything is
// indistinguishable from a clean result. These feed it types that must be
// rejected, and one that must not.
func TestTheTypeGraphGuardActuallyFires(t *testing.T) {
	type withInterface struct {
		Payload any
	}
	type withChannel struct {
		C chan int
	}
	type withUnexported struct {
		Visible string
		hidden  string //nolint:unused // present so the type has an unexported field
	}
	type nested struct {
		Inner []withInterface
	}

	for _, tc := range []struct {
		name       string
		typ        reflect.Type
		wantReject bool
	}{
		{"an interface field", reflect.TypeOf(withInterface{}), true},
		{"an interface behind a slice and a struct", reflect.TypeOf(nested{}), true},
		{"a channel field", reflect.TypeOf(withChannel{}), true},
		{"a struct with unexported fields", reflect.TypeOf(withUnexported{}), true},
		{"the real result type", reflect.TypeOf(types.ScanResult{}), false},
		{"an ordinary struct of strings", reflect.TypeOf(struct{ A, B string }{}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var problems []string
			walkType(tc.typ, "probe", map[reflect.Type]bool{}, &problems, 0)
			if tc.wantReject && len(problems) == 0 {
				t.Errorf("the guard accepted %s, so it would not warn a contributor who "+
					"added one to the result type", tc.name)
			}
			if !tc.wantReject && len(problems) > 0 {
				t.Errorf("the guard rejected %s, which it must accept: %s",
					tc.name, strings.Join(problems, "; "))
			}
		})
	}
}

// TestAnArrayOfStringsIsScrubbed covers the kind that was silently copied.
//
// sanitizeInto's default arm used to take arrays, so an array of strings was
// copied verbatim into the report. No field of that kind exists today, which is
// why nothing caught it; the case is handled now and this asserts it, so the
// handling is not removed as dead code later.
func TestAnArrayOfStringsIsScrubbed(t *testing.T) {
	type holder struct {
		Fixed [2]string
	}
	src := holder{Fixed: [2]string{forgery, "clean"}}
	var dst holder
	sanitizeInto(reflect.ValueOf(&src).Elem(), reflect.ValueOf(&dst).Elem())

	if strings.ContainsRune(dst.Fixed[0], 0x1b) {
		t.Errorf("an array element reached the copy with a raw escape byte: %q", dst.Fixed[0])
	}
	if dst.Fixed[1] != "clean" {
		t.Errorf("an ordinary array element was altered: %q", dst.Fixed[1])
	}
}
