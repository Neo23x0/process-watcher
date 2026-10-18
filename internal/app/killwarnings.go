package app

import (
	"fmt"
	"strings"

	"github.com/Neo23x0/process-watcher/internal/config"
)

// KillWarnings names kill rules that match a watched program itself. The
// descendants of a root that run the root's own image (the workers a master
// forks, a master that re-executes itself on a reload) match such a rule as
// well, so enabling it would kill the service it is meant to protect. The
// rules are only compared with the literal watch patterns: a pattern is a
// substring of an image name, so a rule that matches the pattern text itself
// matches every image that contains it.
func KillWarnings(cfg config.Config) []string {
	k := cfg.Kill
	if !k.Enabled || k.SpareRootImage {
		return []string{}
	}
	usesImage := false
	for _, f := range k.Fields {
		if f == config.KillFieldImage || f == config.KillFieldImagePath {
			usesImage = true
		}
	}
	out := []string{}
	if !usesImage {
		return out
	}
	regexes, _ := k.CompileRegex()
	for _, w := range cfg.Watch.ImageContains {
		for i, s := range k.Strings {
			if strings.Contains(w, s) {
				out = append(out, fmt.Sprintf("kill.strings[%d] %q is contained in the watch pattern %q: every descendant that runs the watched program matches it, so forked workers would be killed (set kill.spare_root_image: true or narrow the rule)", i, s, w))
			}
		}
		for i, re := range regexes {
			if re.MatchString(w) {
				out = append(out, fmt.Sprintf("kill.regex[%d] %q matches the watch pattern %q: every descendant that runs the watched program matches it, so forked workers would be killed (set kill.spare_root_image: true or narrow the rule)", i, re.String(), w))
			}
		}
	}
	return out
}
