// Package killrule evaluates the kill rules of the kill feature.
//
// A rule is either a literal, case-sensitive substring (strings.Contains) or a
// Go regular expression (regexp.MatchString, unanchored). All rules and all
// selected fields are combined with OR; every hit is reported so that one
// action can list all of them.
//
// Only values that are provably complete may be handed in: a Subject field
// that is nil (or an argument beyond the captured prefix) is simply not
// tested. A cut value must never reach this package, otherwise an end anchor
// like "^useradd$" could match a truncated "useradd-long-name".
package killrule

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Neo23x0/process-watcher/internal/config"
)

// Rule types in Hit.Type.
const (
	TypeString = "string"
	TypeRegex  = "regex"
)

// Rules is the compiled rule set.
type Rules struct {
	fields  []string
	strings []string
	regexes []*regexp.Regexp
}

// Compile validates and compiles the rules once at startup.
func Compile(cfg config.KillConfig) (*Rules, error) {
	r := &Rules{}
	for i, f := range cfg.Fields {
		switch f {
		case config.KillFieldImage, config.KillFieldImagePath, config.KillFieldArgv:
			r.fields = append(r.fields, f)
		default:
			return nil, fmt.Errorf("kill.fields[%d]: unknown field %q", i, f)
		}
	}
	if len(r.fields) == 0 {
		return nil, fmt.Errorf("kill.fields: at least one field is required")
	}
	for i, s := range cfg.Strings {
		if s == "" {
			return nil, fmt.Errorf("kill.strings[%d]: empty string", i)
		}
		r.strings = append(r.strings, s)
	}
	for i, p := range cfg.Regex {
		if p == "" {
			return nil, fmt.Errorf("kill.regex[%d]: empty regular expression", i)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("kill.regex[%d]: %w", i, err)
		}
		r.regexes = append(r.regexes, re)
	}
	return r, nil
}

// Count returns the number of rules.
func (r *Rules) Count() int { return len(r.strings) + len(r.regexes) }

// Fields returns the selected fields in configuration order.
func (r *Rules) Fields() []string { return append([]string(nil), r.fields...) }

// UsesField reports whether the given field is selected.
func (r *Rules) UsesField(field string) bool {
	for _, f := range r.fields {
		if f == field {
			return true
		}
	}
	return false
}

// Subject carries the proven-complete values of one process instance. Argv[i]
// is argv[i] of the process; only a complete prefix may be set.
type Subject struct {
	Image     *string
	ImagePath *string
	Argv      []string
}

// Hit is one rule that matched one field.
type Hit struct {
	Ref      string // stable reference: kill.strings[0] or kill.regex[2]
	Type     string // TypeString or TypeRegex
	Pattern  string // the configured string or expression
	Field    string // image, image_path or argv
	ArgIndex int    // argument index for field argv, -1 otherwise

	idx int // position within the strings or regex list, for Retest
}

// Match returns every hit in a deterministic order: strings in configuration
// order, then regular expressions; per rule the fields in configuration order
// and the arguments in ascending index order.
func (r *Rules) Match(s Subject) []Hit {
	var hits []Hit
	test := func(ref, typ, pattern string, idx int, matches func(string) bool) {
		for _, f := range r.fields {
			switch f {
			case config.KillFieldImage:
				if s.Image != nil && matches(*s.Image) {
					hits = append(hits, Hit{Ref: ref, Type: typ, Pattern: pattern, Field: f, ArgIndex: -1, idx: idx})
				}
			case config.KillFieldImagePath:
				if s.ImagePath != nil && matches(*s.ImagePath) {
					hits = append(hits, Hit{Ref: ref, Type: typ, Pattern: pattern, Field: f, ArgIndex: -1, idx: idx})
				}
			case config.KillFieldArgv:
				for i, a := range s.Argv {
					if matches(a) {
						hits = append(hits, Hit{Ref: ref, Type: typ, Pattern: pattern, Field: f, ArgIndex: i, idx: idx})
					}
				}
			}
		}
	}
	for i, str := range r.strings {
		str := str
		test(fmt.Sprintf("kill.strings[%d]", i), TypeString, str, i, func(v string) bool { return strings.Contains(v, str) })
	}
	for i, re := range r.regexes {
		re := re
		test(fmt.Sprintf("kill.regex[%d]", i), TypeRegex, re.String(), i, re.MatchString)
	}
	return hits
}

// Retest reports which of the given hits still hold for the current values of
// their fields. It is used right before the signal: current maps a field to
// its freshly read value (argv entries are addressed by index). A hit whose
// field has no current value does not hold.
func (r *Rules) Retest(hits []Hit, currentImage, currentPath *string, currentArgv []string) []Hit {
	var still []Hit
	for _, h := range hits {
		var val *string
		switch h.Field {
		case config.KillFieldImage:
			val = currentImage
		case config.KillFieldImagePath:
			val = currentPath
		case config.KillFieldArgv:
			if h.ArgIndex >= 0 && h.ArgIndex < len(currentArgv) {
				v := currentArgv[h.ArgIndex]
				val = &v
			}
		}
		if val == nil {
			continue
		}
		if r.holds(h, *val) {
			still = append(still, h)
		}
	}
	return still
}

func (r *Rules) holds(h Hit, value string) bool {
	switch h.Type {
	case TypeString:
		return h.idx < len(r.strings) && strings.Contains(value, r.strings[h.idx])
	case TypeRegex:
		return h.idx < len(r.regexes) && r.regexes[h.idx].MatchString(value)
	}
	return false
}
