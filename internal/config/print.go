package config

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// PrintConfig writes the fully resolved configuration as deterministic YAML:
// the documented key order, a first comment line naming the source file and
// durations in compact form. Secrets are never printed: token_env is the
// variable name only, and the webhook URL has its query values (and any
// credentials) redacted, so a configuration whose URL has a query does not
// round-trip. Otherwise the output loads again through the strict loader to an
// identical Config.
func PrintConfig(w io.Writer, r *Resolved) error {
	if r == nil {
		return errors.New("config: no resolved configuration to print")
	}
	src := r.SourceFile
	if src == "" {
		src = "built-in defaults"
	}
	var b strings.Builder
	b.WriteString("# source: " + commentText(src) + "\n")
	cfg := r.Config
	writeStruct(&b, reflect.ValueOf(&cfg).Elem(), 0, "")
	_, err := io.WriteString(w, b.String())
	return err
}

// writeStruct prints the fields of v in declaration order. Top level
// sections are separated by a blank line.
func writeStruct(b *strings.Builder, v reflect.Value, depth int, prefix string) {
	t := v.Type()
	pad := strings.Repeat("  ", depth)
	for i := range t.NumField() {
		sf := t.Field(i)
		key := yamlKey(sf)
		if key == "-" {
			continue
		}
		path := joinKey(prefix, key)
		if sf.Type.Kind() == reflect.Struct {
			if depth == 0 {
				b.WriteByte('\n')
			}
			fmt.Fprintf(b, "%s%s:\n", pad, key)
			writeStruct(b, v.Field(i), depth+1, path)
			continue
		}
		fmt.Fprintf(b, "%s%s: %s\n", pad, key, scalarText(path, v.Field(i)))
	}
}

func scalarText(path string, v reflect.Value) string {
	k, _ := kindOf(v.Type())
	switch k {
	case kindBool:
		return strconv.FormatBool(v.Bool())
	case kindInt:
		return strconv.FormatInt(v.Int(), 10)
	case kindDuration:
		return formatDuration(time.Duration(v.Int()))
	case kindList:
		items := make([]string, v.Len())
		for i := range items {
			items[i] = yamlString(v.Index(i).String())
		}
		return "[" + strings.Join(items, ", ") + "]"
	}
	s := v.String()
	if path == "outputs.webhook.url" {
		s = redactURL(s)
	}
	return yamlString(s)
}

// formatDuration prints whole seconds as "Ns" (like the documented defaults
// "60s"), whole milliseconds as "Nms" and anything else in Go syntax. All of
// them parse back to the same value.
func formatDuration(d time.Duration) string {
	switch {
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	case d%time.Millisecond == 0:
		return strconv.FormatInt(int64(d/time.Millisecond), 10) + "ms"
	}
	return d.String()
}

var (
	plainRe     = regexp.MustCompile(`^[A-Za-z_/][A-Za-z0-9_./-]*$`)
	keywordsRe  = regexp.MustCompile(`^(?i:true|false|null|yes|no|on|off|y|n)$`)
	redactedVal = "REDACTED"
)

// yamlString renders a string as a plain scalar when that is unambiguous and
// as a double-quoted scalar otherwise.
func yamlString(s string) string {
	if plainRe.MatchString(s) && !keywordsRe.MatchString(s) {
		return s
	}
	return yamlQuote(s)
}

// yamlQuote renders s as a YAML double-quoted scalar.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(`\uFFFD`) // not representable; Resolve rejects such strings
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == 0:
			b.WriteString(`\0`)
		case r == 0x85:
			b.WriteString(`\N`)
		case r == 0x2028:
			b.WriteString(`\L`)
		case r == 0x2029:
			b.WriteString(`\P`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02X`, r)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r > 0xFFFF:
			fmt.Fprintf(&b, `\U%08X`, r)
		default:
			fmt.Fprintf(&b, `\u%04X`, r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// commentText makes s safe for a single comment line.
func commentText(s string) string {
	if strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return yamlQuote(s)
	}
	return s
}

// redactURL replaces the values of all query parameters and any credentials
// or fragment of a URL by a placeholder and hides its path: chat services keep
// the secret of a webhook in the path (like the runtime diagnostics, which
// show only scheme, host and parameter names). It works on the text, so it
// also handles URLs that do not parse.
func redactURL(raw string) string {
	rest, _, hasFragment := strings.Cut(raw, "#")
	base, query, hasQuery := strings.Cut(rest, "?")
	if scheme, after, ok := strings.Cut(base, "://"); ok {
		authority, path, hasPath := strings.Cut(after, "/")
		if i := strings.LastIndexByte(authority, '@'); i >= 0 {
			authority = redactedVal + authority[i:]
		}
		base = scheme + "://" + authority
		if hasPath && path != "" {
			base += "/..."
		} else if hasPath {
			base += "/"
		}
	}
	var b strings.Builder
	b.WriteString(base)
	if hasQuery {
		b.WriteByte('?')
		pairs := strings.Split(query, "&")
		for i, p := range pairs {
			if i > 0 {
				b.WriteByte('&')
			}
			switch key, _, ok := strings.Cut(p, "="); {
			case p == "":
			case ok:
				b.WriteString(key + "=" + redactedVal)
			default:
				b.WriteString(redactedVal)
			}
		}
	}
	if hasFragment {
		b.WriteString("#" + redactedVal)
	}
	return b.String()
}
