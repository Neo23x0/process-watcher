package response

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/killrule"
)

const (
	// summaryRulesMax is the number of rules named in the sentence; the rest is counted.
	summaryRulesMax = 4
	// summaryPatternMax is the length in characters up to which a pattern is quoted whole.
	summaryPatternMax = 80
	// summaryImageMax is the length in characters up to which an image name is quoted whole; the
	// event has it in full in process.image.
	summaryImageMax = 64
)

// killSummary is the sentence of an audit event: what was decided or done, to
// which process, who started it and which rules matched. It repeats facts the
// fields carry, for the person reading the log. It holds no arguments (they
// can contain secrets); the event has them in process.argv.
func killSummary(a *Action, r Result) string {
	var b strings.Builder
	b.WriteString(summaryLead(a.DryRun, r))
	b.WriteByte(' ')
	b.WriteString(summaryTarget(a))
	b.WriteString(summaryWhere(a))
	b.WriteString("; matched ")
	b.WriteString(summaryRules(a.Hits))
	return b.String()
}

// summaryLead says what happened to the target.
func summaryLead(dryRun bool, r Result) string {
	switch r.Outcome {
	case event.OutcomePending:
		if dryRun {
			return "dry run, would kill"
		}
		return "SIGKILL requested for"
	case event.OutcomeDryRun:
		return "dry run, no signal sent, would have killed"
	case event.OutcomeSignalSent:
		return "SIGKILL sent to"
	case event.OutcomeAlreadyExited:
		return "no signal sent, it had already exited:"
	case event.OutcomePermissionDenied:
		return "SIGKILL refused (permission denied) for"
	case event.OutcomeError:
		return "SIGKILL failed for"
	case event.OutcomeSkipped:
		if r.Reason != "" {
			return "not killed, skipped (" + r.Reason + "):"
		}
		return "not killed, skipped:"
	}
	return r.Outcome
}

// summaryTarget names the process the decision is about.
func summaryTarget(a *Action) string {
	p := a.Process
	if p == nil {
		return "an unknown process"
	}
	return fmt.Sprintf("%s (pid %d, exec %d, uid %d)", imageName(p.Image), p.PID, a.ExecIndex, p.UID)
}

// summaryWhere says who started the target and which root it belongs to.
func summaryWhere(a *Action) string {
	switch {
	case a.Parent != nil && a.Root != nil && a.Parent.PID != a.Root.PID:
		return fmt.Sprintf(", started by %s (pid %d) below %s (pid %d)",
			imageName(a.Parent.Image), a.Parent.PID, imageName(a.Root.Image), a.Root.PID)
	case a.Root != nil:
		return fmt.Sprintf(", started by %s (pid %d)", imageName(a.Root.Image), a.Root.PID)
	case a.Parent != nil:
		return fmt.Sprintf(", started by %s (pid %d)", imageName(a.Parent.Image), a.Parent.PID)
	}
	return ""
}

// summaryRules lists the matching rules, one entry per configured rule with
// the fields it matched: kill.regex[5] "<pattern>" in argv[3].
func summaryRules(hits []killrule.Hit) string {
	type entry struct {
		ref, pattern string
		fields       []string
	}
	var entries []*entry
	byRef := map[string]*entry{}
	for _, h := range hits {
		e := byRef[h.Ref]
		if e == nil {
			e = &entry{ref: h.Ref, pattern: h.Pattern}
			byRef[h.Ref] = e
			entries = append(entries, e)
		}
		f := h.Field
		if h.Field == "argv" && h.ArgIndex >= 0 {
			f = fmt.Sprintf("argv[%d]", h.ArgIndex)
		}
		seen := false
		for _, have := range e.fields {
			if have == f {
				seen = true
			}
		}
		if !seen {
			e.fields = append(e.fields, f)
		}
	}
	if len(entries) == 0 {
		return "no rule"
	}
	var parts []string
	for i, e := range entries {
		if i == summaryRulesMax {
			more := len(entries) - summaryRulesMax
			noun := "rules"
			if more == 1 {
				noun = "rule"
			}
			parts = append(parts, fmt.Sprintf("and %d more %s", more, noun))
			break
		}
		// Plain quotes, no Go escaping: a regular expression must read as it was written.
		parts = append(parts, fmt.Sprintf(`%s "%s" in %s`, e.ref, shorten(e.pattern), strings.Join(e.fields, ", ")))
	}
	return strings.Join(parts, "; ")
}

// shorten cuts a long pattern; the full text is in details.rules.
func shorten(p string) string {
	return clean(cut(p, summaryPatternMax))
}

func imageName(p *string) string {
	if p == nil || *p == "" {
		return "an unknown program"
	}
	return clean(cut(*p, summaryImageMax))
}

// cut limits s to n characters.
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "..."
}

// clean makes s safe for a line of text. A file name is chosen by whoever can
// run a program, and the summary is printed by tools that show it as it is
// (jq -r, a terminal): control characters, DEL, the C1 controls and the
// invisible format characters (direction overrides, zero width, byte order
// mark) become \uXXXX, so a name cannot start a fake line, move the cursor or
// reorder the text around it.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x10000 && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)):
			fmt.Fprintf(&b, "\\u%04x", r)
		case r >= 0x10000 && unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, "\\U%08x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
