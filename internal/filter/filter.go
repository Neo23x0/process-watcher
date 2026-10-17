// Package filter implements the literal substring matching used for the watch
// patterns and the output exclusions.
//
// Matching is on the image (the executed file name) and on single arguments,
// never on a joined command line or on serialized event text. Case folding,
// when enabled, is ASCII only (A-Z), independent of any locale or Unicode
// tables: "É" and "é" stay different.
package filter

import (
	"strings"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

// FoldASCII lower-cases the ASCII letters of s and leaves every other byte
// untouched.
func FoldASCII(s string) string {
	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Matcher decides which executed images make a process a tree root. The
// patterns are combined with OR.
type Matcher struct {
	patterns []string
	fold     bool
}

// NewMatcher returns a matcher for the given literal substrings.
func NewMatcher(patterns []string, ignoreCase bool) *Matcher {
	m := &Matcher{fold: ignoreCase}
	for _, p := range patterns {
		if ignoreCase {
			p = FoldASCII(p)
		}
		m.patterns = append(m.patterns, p)
	}
	return m
}

// Match reports whether image contains one of the patterns.
func (m *Matcher) Match(image string) bool {
	if image == "" || len(m.patterns) == 0 {
		return false
	}
	if m.fold {
		image = FoldASCII(image)
	}
	for _, p := range m.patterns {
		if strings.Contains(image, p) {
			return true
		}
	}
	return false
}

// Match is one exclusion string that hit.
type Match struct {
	Field string // "image" or "argv"
	Value string // the configured string
	Index int    // argument index for field "argv", -1 otherwise
}

// Exclusions evaluates exclude.image_contains and exclude.argv_contains. All
// entries are combined with OR.
type Exclusions struct {
	image, imageF []string
	argv, argvF   []string
	fold          bool
}

// NewExclusions builds the exclusion set; ignoreCase is watch.ignore_case.
func NewExclusions(imageContains, argvContains []string, ignoreCase bool) *Exclusions {
	e := &Exclusions{fold: ignoreCase, image: imageContains, argv: argvContains}
	for _, s := range imageContains {
		e.imageF = append(e.imageF, e.f(s))
	}
	for _, s := range argvContains {
		e.argvF = append(e.argvF, e.f(s))
	}
	return e
}

func (e *Exclusions) f(s string) string {
	if e.fold {
		return FoldASCII(s)
	}
	return s
}

// Empty reports whether no exclusion is configured.
func (e *Exclusions) Empty() bool { return len(e.image) == 0 && len(e.argv) == 0 }

// Eval checks the current image and the available arguments of one event and
// returns every exclusion string that hit. Missing or truncated values never
// match: args.List only holds complete arguments, and an unknown image (empty)
// is not tested.
func (e *Exclusions) Eval(image string, args collector.Args) []Match {
	if e.Empty() {
		return nil
	}
	var out []Match
	if image != "" {
		img := e.f(image)
		for i, p := range e.imageF {
			if strings.Contains(img, p) {
				out = append(out, Match{Field: "image", Value: e.image[i], Index: -1})
			}
		}
	}
	if args.State == collector.ArgsCaptured {
		for idx, a := range args.List {
			arg := e.f(a)
			for i, p := range e.argvF {
				if strings.Contains(arg, p) {
					out = append(out, Match{Field: "argv", Value: e.argv[i], Index: idx})
				}
			}
		}
	}
	return out
}
