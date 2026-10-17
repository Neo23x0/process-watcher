package filter

import (
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

func TestFoldASCII(t *testing.T) {
	for in, want := range map[string]string{
		"":          "",
		"nginx":     "nginx",
		"NGINX":     "nginx",
		"Nginx-Dbg": "nginx-dbg",
		"ÉCOLE":     "École", // É is not folded, the ASCII letters are
		"İSTANBUL":  "İstanbul",
	} {
		if got := FoldASCII(in); got != want {
			t.Errorf("FoldASCII(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatcher(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		ignore   bool
		image    string
		want     bool
	}{
		{"substring of the image", []string{"nginx"}, false, "nginx-debug", true},
		{"exact", []string{"nginx"}, false, "nginx", true},
		{"or across patterns", []string{"apache2", "nginx"}, false, "nginx", true},
		{"no match", []string{"nginx"}, false, "python3", false},
		{"case sensitive by default", []string{"nginx"}, false, "NGINX", false},
		{"ignore case", []string{"nginx"}, true, "NGINX", true},
		{"ignore case folds the pattern too", []string{"NgInX"}, true, "nginx", true},
		{"ascii only: non-ASCII letters are not folded", []string{"é"}, true, "É", false},
		{"empty image never matches", []string{"x"}, false, "", false},
		{"no patterns never match", nil, false, "nginx", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewMatcher(tc.patterns, tc.ignore).Match(tc.image); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.image, got, tc.want)
			}
		})
	}
}

func args(list ...string) collector.Args {
	return collector.Args{State: collector.ArgsCaptured, List: list}
}

func TestExclusions(t *testing.T) {
	tests := []struct {
		name       string
		image, arg []string
		ignore     bool
		curImage   string
		curArgs    collector.Args
		want       []Match
	}{
		{"nothing configured", nil, nil, false, "sh", args("sh"), nil},
		{"image substring", []string{"legit"}, nil, false, "legitimate-helper", args(), []Match{{"image", "legit", -1}}},
		{"image does not match", []string{"legit"}, nil, false, "sh", args(), nil},
		{"argument match reports its index", nil, []string{"--health"}, false, "curl", args("curl", "--health-check"), []Match{{"argv", "--health", 1}}},
		{"each argument is tested alone", nil, []string{"a b"}, false, "x", args("a", "b"), nil},
		{"or across image and argv", []string{"curl"}, []string{"-s"}, false, "curl", args("curl", "-s"), []Match{{"image", "curl", -1}, {"argv", "-s", 1}}},
		{"case sensitive", []string{"Curl"}, nil, false, "curl", args(), nil},
		{"ignore case applies to exclusions as well", []string{"Curl"}, []string{"-S"}, true, "CURL", args("x", "-s"), []Match{{"image", "Curl", -1}, {"argv", "-S", 1}}},
		{"missing argv never matches", nil, []string{"x"}, false, "sh", collector.Args{State: collector.ArgsNotCaptured}, nil},
		{"failed argv capture never matches", nil, []string{"x"}, false, "sh", collector.Args{State: collector.ArgsFailed}, nil},
		{"unknown image is not tested", []string{"x"}, nil, false, "", args(), nil},
		{"several hits are all reported", []string{"sh", "dash"}, nil, false, "dash", args(), []Match{{"image", "sh", -1}, {"image", "dash", -1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NewExclusions(tc.image, tc.arg, tc.ignore).Eval(tc.curImage, tc.curArgs)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("match %d: got %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
