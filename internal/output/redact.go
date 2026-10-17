package output

import (
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	redacted     = "[redacted]"
	lastErrorMax = 256 // bound of RemoteStats.LastError in bytes
)

// redactURL renders a webhook URL for logs and errors. Webhook URLs carry
// secrets in the query and, for chat services, in the path, so only the
// scheme, the host and the names of the query parameters survive.
func redactURL(u *url.URL) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(u.Scheme))
	b.WriteString("://")
	b.WriteString(u.Host)
	switch p := u.EscapedPath(); p {
	case "":
	case "/":
		b.WriteByte('/')
	default:
		b.WriteString("/...")
	}
	if u.RawQuery != "" {
		b.WriteByte('?')
		for i, pair := range strings.Split(u.RawQuery, "&") {
			if i > 0 {
				b.WriteByte('&')
			}
			key, _, hasValue := strings.Cut(pair, "=")
			if !hasValue {
				// A bare word may itself be the secret.
				b.WriteString("REDACTED")
				continue
			}
			b.WriteString(sanitizeLine(key, 32))
			b.WriteString("=REDACTED")
		}
	}
	return b.String()
}

// newScrubber returns a function that removes the given secrets from a
// message, neutralizes control characters (no log injection) and bounds the
// length. Longer secrets are replaced first so that one containing another is
// removed completely.
func newScrubber(secrets []string) func(string) string {
	list := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if s != "" {
			list = append(list, s)
		}
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	return func(s string) string {
		for _, sec := range list {
			s = strings.ReplaceAll(s, sec, redacted)
		}
		return sanitizeLine(s, lastErrorMax)
	}
}

// sanitizeLine makes s safe for single-line diagnostics.
func sanitizeLine(s string, limit int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return boundString(s, limit)
}

// boundString cuts s to at most limit bytes (on a rune boundary) and marks the
// cut with "...".
func boundString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
