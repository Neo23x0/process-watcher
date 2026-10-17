package collector

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		cut   bool
		argc  int
		want  []string
		trunc bool
	}{
		{"plain", "sh\x00-c\x00id\x00", false, 3, []string{"sh", "-c", "id"}, false},
		{"empty argument is kept", "a\x00\x00b\x00", false, 3, []string{"a", "", "b"}, false},
		{"unterminated last argument is dropped", "a\x00bb\x00cc", true, 3, []string{"a", "bb"}, true},
		{"cut exactly at an argument boundary", "a\x00bb\x00", true, 3, []string{"a", "bb"}, true},
		{"kernel says more arguments existed", "a\x00", false, 3, []string{"a"}, true},
		{"unknown argc", "a\x00b\x00", false, 0, []string{"a", "b"}, false},
		{"nothing", "", false, 0, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := ParseArgs([]byte(tc.raw), tc.cut, tc.argc)
			if !reflect.DeepEqual(a.List, tc.want) || a.Truncated != tc.trunc || a.State != ArgsCaptured {
				t.Errorf("got %+v, want %v truncated=%v", a, tc.want, tc.trunc)
			}
		})
	}
}

func TestParseArgsLimitsTo32(t *testing.T) {
	raw := strings.Repeat("x\x00", 40)
	a := ParseArgs([]byte(raw), false, 40)
	if len(a.List) != MaxArgs || !a.Truncated {
		t.Fatalf("%d args, truncated=%v", len(a.List), a.Truncated)
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
