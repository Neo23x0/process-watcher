package config

import (
	"cmp"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Upper bounds. They protect consumers from overflow and absurd allocations
// (for example a channel with 2^62 slots); the remaining ranges are the ones
// of the specification.
const (
	maxRotateSizeMB = 1 << 20 // 1 TiB
	maxKeepFiles    = 10000
	maxQueueSize    = 1 << 20
	maxProcesses    = 1 << 24 // well above the largest Linux pid_max (2^22)
	maxRingBufferMB = 1024    // power of two; the kernel needs page multiples

	minUDPBytes = 512
	maxUDPBytes = 65507 // 65535 minus IPv4 and UDP headers
)

var (
	killFieldList = KillFieldImage + ", " + KillFieldImagePath + ", " + KillFieldArgv
	envNameRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// CompileRegex compiles the kill regular expressions with Go's regexp
// package. Resolve has already rejected invalid ones.
func (k KillConfig) CompileRegex() ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, len(k.Regex))
	for i, s := range k.Regex {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("kill.regex[%d]: %w", i, err)
		}
		out[i] = re
	}
	return out, nil
}

type validator struct {
	errs []*Error
}

func (v *validator) add(path, format string, args ...any) {
	v.errs = append(v.errs, errorf(path, format, args...))
}

// validate checks every rule of the configuration and returns all violations
// in the order of the documented configuration, list entries by index.
// requireWatch is false for doctor.
func validate(cfg *Config, requireWatch bool) []*Error {
	v := &validator{}
	v.text(cfg)
	if cfg.ConfigVersion != CurrentVersion {
		v.add("config_version", "unsupported version %d (this program supports version %d)", cfg.ConfigVersion, CurrentVersion)
	}
	v.watch(cfg, requireWatch)
	v.exclude(cfg)
	v.kill(cfg)
	v.file(cfg.Outputs.File)
	v.tcp(cfg.Outputs.TCP)
	v.udp(cfg.Outputs.UDP)
	v.webhook(cfg.Outputs.Webhook)
	v.delivery(cfg.Delivery)
	v.runtime(cfg.Runtime)
	sortErrors(v.errs, cfg)
	return v.errs
}

// sortErrors orders errors by the position of their key in the configuration
// and by list index; the order of the checks above is kept otherwise.
func sortErrors(errs []*Error, cfg *Config) {
	pos := make(map[string]int)
	for i, l := range leaves(cfg) {
		pos[l.Key] = i
	}
	key := func(path string) (int, int) {
		base, rest, _ := strings.Cut(path, "[")
		idx, _ := strconv.Atoi(strings.TrimSuffix(rest, "]"))
		return pos[base], idx
	}
	slices.SortStableFunc(errs, func(a, b *Error) int {
		pa, ia := key(a.Path)
		pb, ib := key(b.Path)
		return cmp.Or(cmp.Compare(pa, pb), cmp.Compare(ia, ib))
	})
}

// text rejects strings that cannot be reproduced faithfully by print-config
// or that no file name, argument or image name can contain.
func (v *validator) text(cfg *Config) {
	check := func(path, s string) {
		switch {
		case !utf8.ValidString(s):
			v.add(path, "must be valid UTF-8")
		case strings.IndexByte(s, 0) >= 0:
			v.add(path, "must not contain NUL characters")
		}
	}
	for _, l := range leaves(cfg) {
		switch {
		case l.Val.Kind() == reflect.String:
			check(l.Key, l.Val.String())
		case l.Val.Kind() == reflect.Slice:
			for i := range l.Val.Len() {
				check(fmt.Sprintf("%s[%d]", l.Key, i), l.Val.Index(i).String())
			}
		}
	}
}

// nonEmpty rejects empty entries of a search string list.
func (v *validator) nonEmpty(path string, list []string) {
	for i, s := range list {
		if s == "" {
			v.add(fmt.Sprintf("%s[%d]", path, i), "must not be empty")
		}
	}
}

func (v *validator) intRange(path string, n, lo, hi int) {
	if n < lo || n > hi {
		v.add(path, "must be between %d and %d, got %d", lo, hi, n)
	}
}

func (v *validator) positive(path string, d time.Duration) {
	if d <= 0 {
		v.add(path, "must be a positive duration, got %s", d)
	}
}

func (v *validator) watch(cfg *Config, requireWatch bool) {
	w := cfg.Watch
	if requireWatch && len(w.ImageContains) == 0 {
		v.add("watch.image_contains", "at least one pattern is required (set watch.image_contains or pass --watch-image-contains)")
	}
	v.nonEmpty("watch.image_contains", w.ImageContains)
	if w.MaxDepth < 0 {
		v.add("watch.max_depth", "must be 0 (unlimited) or greater, got %d", w.MaxDepth)
	}
}

func (v *validator) exclude(cfg *Config) {
	e := cfg.Exclude
	v.nonEmpty("exclude.image_contains", e.ImageContains)
	v.nonEmpty("exclude.argv_contains", e.ArgvContains)
	if e.Scope != ScopeRemote && e.Scope != ScopeAll {
		v.add("exclude.scope", "must be %q or %q, got %q", ScopeRemote, ScopeAll, e.Scope)
	}
	if len(e.ArgvContains) > 0 && !cfg.Capture.Argv {
		v.add("exclude.argv_contains", "requires capture.argv: true (set capture.argv: true or pass --capture-argv=true)")
	}
}

// kill applies the validation rules of the kill feature. Shape errors are
// reported even when kill is disabled; the cross-checks only when enabled.
func (v *validator) kill(cfg *Config) {
	k := cfg.Kill
	if len(k.Fields) == 0 {
		v.add("kill.fields", "must list at least one field (allowed: %s)", killFieldList)
	}
	for i, f := range k.Fields {
		path := fmt.Sprintf("kill.fields[%d]", i)
		switch f {
		case KillFieldImage, KillFieldImagePath:
		case KillFieldArgv:
			if k.Enabled && !cfg.Capture.Argv {
				v.add(path, `"argv" requires capture.argv: true (set capture.argv: true or pass --capture-argv=true; argument capture is never enabled implicitly)`)
			}
		case "":
			v.add(path, "must not be empty (allowed: %s)", killFieldList)
		default:
			v.add(path, "unknown field %q (allowed: %s)", f, killFieldList)
		}
	}
	v.nonEmpty("kill.strings", k.Strings)
	for i, expr := range k.Regex {
		path := fmt.Sprintf("kill.regex[%d]", i)
		if expr == "" {
			v.add(path, "must not be empty")
			continue
		}
		if _, err := regexp.Compile(expr); err != nil {
			v.add(path, "invalid regular expression: %v", err)
		}
	}
	if k.Enabled && len(k.Strings)+len(k.Regex) == 0 {
		v.add("kill.enabled", "requires at least one rule: set kill.strings or kill.regex (--kill-string, --kill-regex) or disable kill")
	}
}

func (v *validator) file(f FileOutput) {
	switch {
	case f.Path == "":
		v.add("outputs.file.path", "must not be empty")
	case strings.HasSuffix(f.Path, "/"), isDirName(filepath.Base(filepath.Clean(f.Path))):
		v.add("outputs.file.path", "must name a file, not a directory")
	}
	v.intRange("outputs.file.rotate_size_mb", f.RotateSizeMB, 1, maxRotateSizeMB)
	v.intRange("outputs.file.keep_files", f.KeepFiles, 1, maxKeepFiles)
	v.positive("outputs.file.sync_interval", f.SyncInterval)
}

func isDirName(base string) bool {
	return base == "." || base == ".." || base == string(filepath.Separator)
}

func (v *validator) tcp(t TCPOutput) {
	if t.Address != "" {
		if msg := checkHostPort(t.Address); msg != "" {
			v.add("outputs.tcp.address", "invalid address %q: %s", t.Address, msg)
		}
	}
	if t.CAFile != "" && !t.TLS {
		v.add("outputs.tcp.ca_file", "requires outputs.tcp.tls: true (set tcp.tls or pass --tcp-tls)")
	}
	if t.ServerName != "" {
		if !t.TLS {
			v.add("outputs.tcp.server_name", "requires outputs.tcp.tls: true (set tcp.tls or pass --tcp-tls)")
		}
		if msg := checkServerName(t.ServerName); msg != "" {
			v.add("outputs.tcp.server_name", "invalid server name %q: %s", t.ServerName, msg)
		}
	}
}

func (v *validator) udp(u UDPOutput) {
	if u.Address != "" {
		if msg := checkHostPort(u.Address); msg != "" {
			v.add("outputs.udp.address", "invalid address %q: %s", u.Address, msg)
		}
	}
	v.intRange("outputs.udp.max_bytes", u.MaxBytes, minUDPBytes, maxUDPBytes)
}

func (v *validator) webhook(w WebhookOutput) {
	// Messages about the URL never repeat it: query parameters may be secrets.
	if w.URL != "" {
		if msg := checkWebhookURL(w.URL); msg != "" {
			v.add("outputs.webhook.url", "%s", msg)
		}
	}
	if w.TokenEnv != "" && !envNameRe.MatchString(w.TokenEnv) {
		v.add("outputs.webhook.token_env", "must be the name of an environment variable (letters, digits and '_', not starting with a digit), not the token itself")
	}
	v.positive("outputs.webhook.timeout", w.Timeout)
}

func (v *validator) delivery(d DeliveryConfig) {
	v.intRange("delivery.queue_size", d.QueueSize, 1, maxQueueSize)
	v.positive("delivery.connect_timeout", d.ConnectTimeout)
	v.positive("delivery.write_timeout", d.WriteTimeout)
	if d.MaxRetries < 0 {
		v.add("delivery.max_retries", "must be 0 or greater, got %d", d.MaxRetries)
	}
}

func (v *validator) runtime(r RuntimeConfig) {
	if n := r.RingBufferMB; n < 1 || n > maxRingBufferMB || n&(n-1) != 0 {
		v.add("runtime.ring_buffer_mb", "must be a power of two between 1 and %d (MiB), got %d", maxRingBufferMB, n)
	}
	v.intRange("runtime.max_processes", r.MaxProcesses, 1, maxProcesses)
	v.positive("runtime.health_interval", r.HealthInterval)
	v.positive("runtime.reconcile_interval", r.ReconcileInterval)
	v.positive("runtime.shutdown_timeout", r.ShutdownTimeout)
}
