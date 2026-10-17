package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSanitizeReplacesEveryInvalidByte(t *testing.T) {
	for in, want := range map[string]string{
		"plain":          "plain",
		"unicode é ✓":    "unicode é ✓",
		"a\xffb":         "a�b",
		"x\xff\xfey":     "x��y",
		"\xc3":           "�",  // truncated two byte sequence
		"\xe2\x82":       "��", // truncated three byte sequence
		"ok\xf0\x28\x8c": "ok�(�",
	} {
		got, changed := Sanitize(in)
		if got != want || changed != (in != want) {
			t.Errorf("Sanitize(%q) = %q, %v; want %q", in, got, changed, want)
		}
	}
}

func TestTimeFormatHasNineDigits(t *testing.T) {
	b, _ := json.Marshal(Time(time.Date(2026, 10, 17, 12, 0, 0, 124_000_000, time.FixedZone("x", 3600))))
	if string(b) != `"2026-10-17T11:00:00.124000000Z"` {
		t.Errorf("%s", b)
	}
}

func TestMarshalLineIsOneLineWithUnescapedHTML(t *testing.T) {
	arg := "a\nb\"c<d>&e f"
	ev := &Event{Process: &Process{Argv: []string{arg}}}
	line, err := ev.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(line), "\n") != 1 || !strings.HasSuffix(string(line), "}\n") {
		t.Fatalf("not exactly one terminated line: %q", line)
	}
	var back Event
	if err := json.Unmarshal(line, &back); err != nil || back.Process.Argv[0] != arg {
		t.Fatalf("round trip lost the argument: %v %+v", err, back.Process)
	}
	if !strings.Contains(string(line), "<d>&e") {
		t.Errorf("HTML characters must stay literal: %s", line)
	}
}

func TestUUIDv4(t *testing.T) {
	a, b := NewUUID(), NewUUID()
	if a == b || len(a) != 36 || a[14] != '4' || !strings.ContainsRune("89ab", rune(a[19])) {
		t.Errorf("%s %s", a, b)
	}
}

func TestProcessID(t *testing.T) {
	if got := ProcessID("b53c175a-2d90-4d0c-8c94-dfc2c15eb199", 1235, 9000000000000); got != "b53c175a-2d90-4d0c-8c94-dfc2c15eb199:1235:9000000000000" {
		t.Error(got)
	}
}
