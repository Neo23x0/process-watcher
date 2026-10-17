package killrule

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/config"
)

func sp(s string) *string { return &s }

func compile(t *testing.T, fields, strs, regexes []string) *Rules {
	t.Helper()
	r, err := Compile(config.KillConfig{Enabled: true, Fields: fields, Strings: strs, Regex: regexes})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.KillConfig
		want string
	}{
		{"unknown field", config.KillConfig{Fields: []string{"cmdline"}}, "kill.fields[0]"},
		{"empty field list", config.KillConfig{Fields: nil}, "kill.fields"},
		{"empty string", config.KillConfig{Fields: []string{"image"}, Strings: []string{"a", ""}}, "kill.strings[1]"},
		{"empty regex", config.KillConfig{Fields: []string{"image"}, Regex: []string{""}}, "kill.regex[0]"},
		{"broken regex", config.KillConfig{Fields: []string{"image"}, Regex: []string{"ok", "(unclosed"}}, "kill.regex[1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error naming %s", err, tc.want)
			}
		})
	}
}

func TestMatchSemantics(t *testing.T) {
	tests := []struct {
		name    string
		fields  []string
		strs    []string
		regexes []string
		subj    Subject
		want    []string // "ref field[:idx]"
	}{
		{"substring in image", []string{"image"}, []string{"helper"}, nil, Subject{Image: sp("demo-long-running-helper")}, []string{"kill.strings[0] image"}},
		{"strings are case sensitive", []string{"image"}, []string{"Helper"}, nil, Subject{Image: sp("helper")}, nil},
		{"regex is unanchored by default", []string{"image"}, nil, []string{"add"}, Subject{Image: sp("useradd")}, []string{"kill.regex[0] image"}},
		{"anchors need the whole value", []string{"image"}, nil, []string{`^(useradd|usermod)$`}, Subject{Image: sp("useradd-wrapper")}, nil},
		{"anchored regex hits the whole value", []string{"image"}, nil, []string{`^(useradd|usermod)$`}, Subject{Image: sp("usermod")}, []string{"kill.regex[0] image"}},
		{"(?i) makes a regex case insensitive", []string{"image"}, nil, []string{`(?i)^useradd$`}, Subject{Image: sp("UserAdd")}, []string{"kill.regex[0] image"}},
		{"argv: every argument alone, argv[0] included", []string{"argv"}, []string{"useradd"}, nil,
			Subject{Argv: []string{"sh", "-c", "useradd bob"}}, []string{"kill.strings[0] argv:2"}},
		{"argv: no joining of arguments", []string{"argv"}, []string{"-c useradd"}, nil, Subject{Argv: []string{"sh", "-c", "useradd"}}, nil},
		{"argv: all matching arguments are reported", []string{"argv"}, []string{"x"}, nil,
			Subject{Argv: []string{"x", "y", "xx"}}, []string{"kill.strings[0] argv:0", "kill.strings[0] argv:2"}},
		{"fields are OR", []string{"image", "image_path"}, []string{"bin"}, nil,
			Subject{Image: sp("tool"), ImagePath: sp("/usr/bin/tool")}, []string{"kill.strings[0] image_path"}},
		{"a field that was not handed in is not tested", []string{"image", "argv"}, []string{"x"}, nil, Subject{Image: sp("a")}, nil},
		{"unselected fields are ignored", []string{"image"}, []string{"x"}, nil, Subject{Image: sp("a"), ImagePath: sp("/x/a"), Argv: []string{"x"}}, nil},
		{"several rules hit together, strings first then regexes", []string{"image"}, []string{"use", "add"}, []string{"^user"},
			Subject{Image: sp("useradd")}, []string{"kill.strings[0] image", "kill.strings[1] image", "kill.regex[0] image"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := compile(t, tc.fields, tc.strs, tc.regexes)
			var got []string
			for _, h := range r.Match(tc.subj) {
				s := h.Ref + " " + h.Field
				if h.ArgIndex >= 0 {
					s += ":" + string(rune('0'+h.ArgIndex))
				}
				got = append(got, s)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHitDescribesTheRule(t *testing.T) {
	r := compile(t, []string{"image"}, nil, []string{`^(useradd|usermod)$`})
	h := r.Match(Subject{Image: sp("usermod")})
	if len(h) != 1 || h[0].Ref != "kill.regex[0]" || h[0].Type != TypeRegex || h[0].Pattern != `^(useradd|usermod)$` || h[0].ArgIndex != -1 {
		t.Fatalf("%+v", h)
	}
}

func TestRetest(t *testing.T) {
	r := compile(t, []string{"image", "argv"}, []string{"helper"}, []string{`^sh$`})
	hits := r.Match(Subject{Image: sp("sh"), Argv: []string{"sh", "run-helper"}})
	if len(hits) != 3 {
		t.Fatalf("setup: %+v", hits)
	}

	same := r.Retest(hits, sp("sh"), nil, []string{"sh", "run-helper"})
	if len(same) != 3 {
		t.Errorf("unchanged values must keep all hits, got %+v", same)
	}
	// The program changed (exec'd something else), the arguments are gone.
	if got := r.Retest(hits, sp("curl"), nil, []string{"curl"}); len(got) != 0 {
		t.Errorf("hits must not survive a changed image and argv: %+v", got)
	}
	// Only the argument hit survives; the image no longer matches.
	if got := r.Retest(hits, sp("bash"), nil, []string{"x", "run-helper"}); len(got) != 1 || got[0].Field != "argv" {
		t.Errorf("got %+v", got)
	}
	// Nothing could be read: nothing is proven.
	if got := r.Retest(hits, nil, nil, nil); len(got) != 0 {
		t.Errorf("unreadable current values prove nothing: %+v", got)
	}
}
