package collector

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		cut     bool
		argc    int
		want    []string
		trunc   bool
		partial string // the expected partial argument, "" for none
	}{
		{"plain", "sh\x00-c\x00id\x00", false, 3, []string{"sh", "-c", "id"}, false, ""},
		{"empty argument is kept", "a\x00\x00b\x00", false, 3, []string{"a", "", "b"}, false, ""},
		{"unterminated last argument is kept apart", "a\x00bb\x00cc", true, 3, []string{"a", "bb"}, true, "cc"},
		{"cut exactly at an argument boundary", "a\x00bb\x00", true, 3, []string{"a", "bb"}, true, ""},
		{"kernel says more arguments existed", "a\x00", false, 3, []string{"a"}, true, ""},
		{"unknown argc", "a\x00b\x00", false, 0, []string{"a", "b"}, false, ""},
		{"nothing", "", false, 0, nil, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := ParseArgs([]byte(tc.raw), tc.cut, tc.argc, 0, ArgLimits{})
			if !reflect.DeepEqual(a.List, tc.want) || a.Truncated != tc.trunc || a.State != ArgsCaptured {
				t.Errorf("got %+v, want %v truncated=%v", a, tc.want, tc.trunc)
			}
			switch {
			case tc.partial == "" && a.Partial != nil:
				t.Errorf("unexpected partial argument %+v", a.Partial)
			case tc.partial != "" && (a.Partial == nil || a.Partial.Value != tc.partial || a.Partial.Index != len(tc.want)):
				t.Errorf("partial argument %+v, want %q at index %d", a.Partial, tc.partial, len(tc.want))
			}
			if a.Complete() == tc.trunc {
				t.Errorf("Complete() = %v with truncated=%v", a.Complete(), tc.trunc)
			}
		})
	}
}

func TestParseArgsLimitsTo32ByDefault(t *testing.T) {
	raw := strings.Repeat("x\x00", 40)
	a := ParseArgs([]byte(raw), false, 40, len(raw), ArgLimits{})
	if len(a.List) != DefaultMaxArgs || !a.Truncated || a.Partial != nil {
		t.Fatalf("%d args, truncated=%v, partial=%v", len(a.List), a.Truncated, a.Partial)
	}
	if a.Limits != DefaultArgLimits() {
		t.Errorf("limits %+v", a.Limits)
	}
}

func TestParseArgsHonoursTheConfiguredCount(t *testing.T) {
	raw := strings.Repeat("x\x00", 10)
	a := ParseArgs([]byte(raw), false, 10, len(raw), ArgLimits{MaxArgs: 3, MaxBytes: 4096})
	if len(a.List) != 3 || !a.Truncated || a.Limits.MaxArgs != 3 {
		t.Fatalf("%+v", a)
	}
	b := ParseArgs([]byte(raw), false, 10, len(raw), ArgLimits{MaxArgs: 64, MaxBytes: 4096})
	if len(b.List) != 10 || b.Truncated {
		t.Fatalf("%+v", b)
	}
}

// The cut inline command of a shell is the case this package exists for: the
// list holds sh, -c and --, the command is kept as the partial argument, and the
// totals say how much was missing.
func TestParseArgsKeepsTheCutInlineCommandApart(t *testing.T) {
	cmd := strings.Repeat("A", 5000)
	full := "sh\x00-c\x00--\x00" + cmd + "\x00"
	raw := full[:4096]
	a := ParseArgs([]byte(raw), true, 4, len(full), ArgLimits{})
	if !reflect.DeepEqual(a.List, []string{"sh", "-c", "--"}) || !a.Truncated {
		t.Fatalf("list %q truncated=%v", a.List, a.Truncated)
	}
	if a.Partial == nil || a.Partial.Index != 3 || len(a.Partial.Value) != 4096-9 || a.Partial.Value != cmd[:4096-9] {
		t.Fatalf("partial %+v", a.Partial)
	}
	if a.TotalBytes != len(full) || a.CapturedBytes != 4096 || a.Argc != 4 {
		t.Errorf("totals %+v", a)
	}
}

func TestArgLimitsNormalized(t *testing.T) {
	if got := (ArgLimits{}).Normalized(); got != DefaultArgLimits() {
		t.Errorf("%+v", got)
	}
	if got := (ArgLimits{MaxArgs: 5}).Normalized(); got.MaxArgs != 5 || got.MaxBytes != DefaultMaxArgBytes {
		t.Errorf("%+v", got)
	}
}

func TestKeyAndStats(t *testing.T) {
	if !(Key{}).IsZero() || (Key{TGID: 1}).IsZero() {
		t.Error("IsZero")
	}
	if got := (Stats{LostFork: 1, LostExec: 2, LostExit: 3}).Lost(); got != 6 {
		t.Errorf("Lost %d", got)
	}
	if KindFork.String() != "fork" || KindExec.String() != "exec" || KindExit.String() != "exit" || Kind(9).String() != "kind(9)" {
		t.Error("Kind.String")
	}
	err := &PrerequisiteError{Check: "pid namespace", Detail: "nested"}
	if !strings.Contains(err.Error(), "pid namespace") || err.Unwrap() != nil {
		t.Error("PrerequisiteError")
	}
}
