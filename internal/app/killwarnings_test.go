package app

import (
	"strings"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/config"
)

func warnCfg(watch []string, kill config.KillConfig) config.Config {
	c := config.Default()
	c.Watch.ImageContains = watch
	c.Kill = kill
	return c
}

func TestKillWarnings(t *testing.T) {
	enabled := func(fields []string, strs, regex []string, spare bool) config.KillConfig {
		return config.KillConfig{Enabled: true, Fields: fields, Strings: strs, Regex: regex, SpareRootImage: spare}
	}
	tests := []struct {
		name  string
		cfg   config.Config
		want  []string // fragments of the expected warnings, in order
		quiet bool
	}{
		{"a string that is part of the watch pattern", warnCfg([]string{"php-fpm"}, enabled([]string{"image"}, []string{"php"}, nil, false)),
			[]string{`kill.strings[0] "php" is contained in the watch pattern "php-fpm"`}, false},
		{"an unanchored regex that matches the watch pattern", warnCfg([]string{"php-fpm"}, enabled([]string{"image"}, nil, []string{`^php`}, false)),
			[]string{`kill.regex[0] "^php" matches the watch pattern "php-fpm"`}, false},
		{"image_path is covered as well", warnCfg([]string{"php-fpm"}, enabled([]string{"image_path"}, []string{"php-fpm"}, nil, false)),
			[]string{"kill.strings[0]"}, false},
		{"one warning per rule and pattern", warnCfg([]string{"php-fpm", "php-cgi"}, enabled([]string{"image"}, []string{"php"}, nil, false)),
			[]string{`"php-fpm"`, `"php-cgi"`}, false},
		{"an anchored rule for another program is fine", warnCfg([]string{"php-fpm"}, enabled([]string{"image"}, nil, []string{`^(dash|bash)$`, `^php[0-9.]*$`}, false)), nil, true},
		{"the guard removes the reason to warn", warnCfg([]string{"php-fpm"}, enabled([]string{"image"}, []string{"php"}, nil, true)), nil, true},
		{"argv-only rules do not select the image", warnCfg([]string{"php-fpm"}, enabled([]string{"argv"}, []string{"php"}, nil, false)), nil, true},
		{"disabled kill feature", warnCfg([]string{"php-fpm"}, config.KillConfig{Enabled: false, Fields: []string{"image"}, Strings: []string{"php"}}), nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := KillWarnings(tc.cfg)
			if got == nil {
				t.Fatal("the result is serialized as a JSON array and must never be nil")
			}
			if tc.quiet && len(got) != 0 {
				t.Fatalf("unexpected warnings: %v", got)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d warnings, want %d: %v", len(got), len(tc.want), got)
			}
			for i, frag := range tc.want {
				if !strings.Contains(got[i], frag) {
					t.Errorf("warning %d is %q, want it to contain %q", i, got[i], frag)
				}
			}
		})
	}
}
