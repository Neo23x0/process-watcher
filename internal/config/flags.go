package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// flagSpec binds one command line flag to one YAML leaf. flagSpecs is the
// single source of truth for flag registration, flag application and --help.
type flagSpec struct {
	Name    string // flag name without leading dashes
	Key     string // dotted YAML key of the leaf, e.g. "outputs.file.path"
	Arg     string // value placeholder for --help; empty for boolean flags
	Section string // heading in --help
	Help    string
}

// Section headings in --help, in display order.
const (
	secWatch    = "Watch"
	secExclude  = "Exclude"
	secCapture  = "Capture"
	secKill     = "Kill"
	secLog      = "Local log file"
	secTCP      = "TCP output"
	secUDP      = "UDP output"
	secWebhook  = "Webhook output"
	secDelivery = "Delivery"
	secRuntime  = "Runtime"
)

// flagSpecs lists a flag for every YAML leaf except config_version, which is
// structural and has no operative flag.
var flagSpecs = []flagSpec{
	{"watch-image-contains", "watch.image_contains", "STRING", secWatch,
		"Observe the process trees rooted at processes whose executed image file name contains STRING (literal substring; entries are ORed). At least one is required, except for doctor."},
	{"watch-ignore-case", "watch.ignore_case", "", secWatch,
		"Match watch and exclude strings with ASCII case folding instead of case-sensitively."},
	{"watch-max-depth", "watch.max_depth", "N", secWatch,
		"Emit process events only down to this depth below the root (the root has depth 0); 0 means unlimited. Tracking and kill rules are not limited by it."},

	{"exclude-image-contains", "exclude.image_contains", "STRING", secExclude,
		"Mark process events whose current image file name contains STRING as excluded (literal substring; ORed)."},
	{"exclude-argv-contains", "exclude.argv_contains", "STRING", secExclude,
		"Mark process events with a single argument containing STRING as excluded (ORed). Requires --capture-argv=true."},
	{"exclude-scope", "exclude.scope", "SCOPE", secExclude,
		"Effect of exclusions: remote keeps excluded events in the local log and withholds them from TCP, UDP and webhook; all suppresses them everywhere."},

	{"capture-argv", "capture.argv", "", secCapture,
		"Capture process arguments at exec time (limits: --capture-argv-max-args and --capture-argv-max-bytes). Arguments can contain credentials."},
	{"capture-argv-max-args", "capture.argv_max_args", "N", secCapture,
		fmt.Sprintf("Capture at most N arguments per exec (%d to %d, default 32). Requires --capture-argv=true. More arguments are reported as incomplete (argv_complete: false).", minArgvMaxArgs, maxArgvMaxArgs)},
	{"capture-argv-max-bytes", "capture.argv_max_bytes", "N", secCapture,
		fmt.Sprintf("Capture at most N raw argument bytes per exec, arguments plus their NUL terminators (%d to %d, default 4096). Requires --capture-argv=true. A longer argument list is reported as incomplete; the cut argument is kept separately in argv_capture.partial and never used for matching.", minArgvMaxBytes, maxArgvMaxBytes)},

	{"kill-enabled", "kill.enabled", "", secKill,
		"Enable rule based termination of observed descendant processes with SIGKILL (see the note below this section)."},
	{"kill-dry-run", "kill.dry_run", "", secKill,
		"Evaluate the kill rules and write the audit events, but never send a signal."},
	{"kill-field", "kill.fields", "FIELD", secKill,
		"Field the kill rules are matched against: image, image_path or argv (ORed). argv requires --capture-argv=true."},
	{"kill-string", "kill.strings", "STRING", secKill,
		"Kill rule: literal, case-sensitive substring (ORed with all other rules)."},
	{"kill-regex", "kill.regex", "REGEX", secKill,
		"Kill rule: Go (RE2) regular expression. It is unanchored: use ^ and $ for the whole value and (?i) to ignore case."},

	{"log-file", "outputs.file.path", "PATH", secLog,
		"Mandatory local JSONL log. A relative path is resolved against the working directory."},
	{"log-rotate-size-mb", "outputs.file.rotate_size_mb", "MIB", secLog,
		fmt.Sprintf("Rotate the log before a line would grow the active file beyond this size (MiB, 1 to %d).", maxRotateSizeMB)},
	{"log-keep-files", "outputs.file.keep_files", "N", secLog,
		fmt.Sprintf("Rotated archives kept in addition to the active file (1 to %d).", maxKeepFiles)},
	{"log-sync-interval", "outputs.file.sync_interval", "DURATION", secLog,
		"Maximum time between fsync calls on the log."},

	{"tcp-address", "outputs.tcp.address", "HOST:PORT", secTCP,
		"Send events to this TCP endpoint as newline separated JSON (IPv6 in brackets, e.g. [2001:db8::10]:9000); empty disables TCP."},
	{"tcp-tls", "outputs.tcp.tls", "", secTCP,
		"Use TLS for the TCP output, with certificate and host name verification."},
	{"tcp-ca-file", "outputs.tcp.ca_file", "PATH", secTCP,
		"PEM file with the CA certificates to trust instead of the system trust store. Requires --tcp-tls. A relative path is resolved against the working directory."},
	{"tcp-server-name", "outputs.tcp.server_name", "NAME", secTCP,
		"Server name used for TLS verification (default: the host of --tcp-address). Requires --tcp-tls."},

	{"udp-address", "outputs.udp.address", "HOST:PORT", secUDP,
		"Send each event as one datagram to this UDP endpoint; empty disables UDP."},
	{"udp-max-bytes", "outputs.udp.max_bytes", "N", secUDP,
		fmt.Sprintf("Largest datagram in bytes (%d to %d). Larger events are not sent over UDP.", minUDPBytes, maxUDPBytes)},

	{"webhook-url", "outputs.webhook.url", "URL", secWebhook,
		"POST each event as one JSONL line to this http:// or https:// URL (no credentials, no fragment); empty disables the webhook. Query values are redacted in diagnostics."},
	{"webhook-token-env", "outputs.webhook.token_env", "NAME", secWebhook,
		"Name of an environment variable holding a bearer token for the webhook. It must be set and non-empty when the webhook is enabled."},
	{"webhook-timeout", "outputs.webhook.timeout", "DURATION", secWebhook,
		"Timeout of one webhook request."},

	{"queue-size", "delivery.queue_size", "N", secDelivery,
		fmt.Sprintf("Capacity of each remote output queue in events (1 to %d). When it is full, the newest event is dropped for that output only.", maxQueueSize)},
	{"connect-timeout", "delivery.connect_timeout", "DURATION", secDelivery,
		"Timeout for establishing a remote connection."},
	{"write-timeout", "delivery.write_timeout", "DURATION", secDelivery,
		"Timeout of each write to a remote endpoint."},
	{"max-retries", "delivery.max_retries", "N", secDelivery,
		"Retries after a failed TCP or webhook delivery; 0 disables retries, so a delivery is attempted 1 plus this many times."},

	{"ring-buffer-mb", "runtime.ring_buffer_mb", "MIB", secRuntime,
		fmt.Sprintf("Size of the BPF ring buffer in MiB: a power of two from 1 to %d.", maxRingBufferMB)},
	{"max-processes", "runtime.max_processes", "N", secRuntime,
		fmt.Sprintf("Maximum number of tracked process instances including ancestors still needed (1 to %d).", maxProcesses)},
	{"health-interval", "runtime.health_interval", "DURATION", secRuntime,
		"Interval of the periodic agent.health events."},
	{"reconcile-interval", "runtime.reconcile_interval", "DURATION", secRuntime,
		"Interval of the process inventory reconciliation."},
	{"shutdown-timeout", "runtime.shutdown_timeout", "DURATION", secRuntime,
		"Time allowed for draining the remote queues on SIGINT or SIGTERM."},
}

// kind is the shape of a YAML leaf.
type kind int

const (
	kindString kind = iota
	kindBool
	kindInt
	kindDuration
	kindList
)

var durationType = reflect.TypeFor[time.Duration]()

// kindOf maps a Go field type to its leaf kind. ok is false for types the
// configuration does not support.
func kindOf(t reflect.Type) (k kind, ok bool) {
	switch {
	case t == durationType:
		return kindDuration, true
	case t.Kind() == reflect.Bool:
		return kindBool, true
	case t.Kind() == reflect.Int:
		return kindInt, true
	case t.Kind() == reflect.String:
		return kindString, true
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.String:
		return kindList, true
	}
	return 0, false
}

// yamlKey returns the YAML key of a struct field, or "-" if it has none.
func yamlKey(sf reflect.StructField) string {
	name, _, _ := strings.Cut(sf.Tag.Get("yaml"), ",")
	if name == "" {
		return strings.ToLower(sf.Name)
	}
	return name
}

func joinKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// leaf is one scalar or list setting of a Config.
type leaf struct {
	Key string
	Val reflect.Value
}

// leaves returns every leaf of cfg in declaration order (which is also the
// documented key order).
func leaves(cfg *Config) []leaf {
	var out []leaf
	var walk func(v reflect.Value, prefix string)
	walk = func(v reflect.Value, prefix string) {
		t := v.Type()
		for i := range t.NumField() {
			sf := t.Field(i)
			key := yamlKey(sf)
			if key == "-" {
				continue
			}
			path := joinKey(prefix, key)
			if sf.Type.Kind() == reflect.Struct {
				walk(v.Field(i), path)
				continue
			}
			out = append(out, leaf{Key: path, Val: v.Field(i)})
		}
	}
	walk(reflect.ValueOf(cfg).Elem(), "")
	return out
}

func leafMap(cfg *Config) map[string]reflect.Value {
	ls := leaves(cfg)
	m := make(map[string]reflect.Value, len(ls))
	for _, l := range ls {
		m[l.Key] = l.Val
	}
	return m
}

// normalize replaces nil lists by empty ones so that equal configurations
// compare equal.
func normalize(cfg *Config) {
	for _, l := range leaves(cfg) {
		if l.Val.Kind() == reflect.Slice && l.Val.IsNil() {
			l.Val.Set(reflect.MakeSlice(l.Val.Type(), 0, 0))
		}
	}
}

// rawValue records every occurrence of a flag. Values are parsed later so
// that problems are reported as *Error naming the flag.
type rawValue struct {
	vals   []string
	isBool bool
}

func (v *rawValue) Set(s string) error {
	v.vals = append(v.vals, s)
	return nil
}

func (v *rawValue) String() string {
	if v == nil {
		return ""
	}
	return strings.Join(v.vals, ",")
}

// IsBoolFlag lets "--flag" without a value mean true.
func (v *rawValue) IsBoolFlag() bool { return v != nil && v.isBool }

// cmdline is the parsed command line.
type cmdline struct {
	command Command
	help    bool
	version bool
	config  *rawValue            // --config, nil if absent
	set     map[string]*rawValue // explicitly set YAML flags by flag name
}

// parseArgs parses the command line with the standard flag package. Flags may
// appear before and after the subcommand. --help and --version win over any
// later problem of the command line.
func parseArgs(args []string) (*cmdline, error) {
	fs := flag.NewFlagSet("process-watcher", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	values := make(map[string]*rawValue, len(flagSpecs)+1)
	for _, spec := range flagSpecs {
		k, _ := kindOf(leafType(spec.Key))
		v := &rawValue{isBool: k == kindBool}
		values[spec.Name] = v
		fs.Var(v, spec.Name, spec.Help)
	}
	values["config"] = &rawValue{}
	fs.Var(values["config"], "config", "YAML configuration file")
	help := fs.Bool("help", false, "show help")
	h := fs.Bool("h", false, "show help")
	version := fs.Bool("version", false, "show the version")

	var (
		name     string // first positional argument: the subcommand
		flagErr  error
		usageErr error
	)
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			flagErr = err
			break
		}
		pos := fs.Args()
		if len(pos) == 0 {
			break
		}
		if name == "" {
			name = pos[0]
		} else if usageErr == nil {
			usageErr = &UsageError{Msg: fmt.Sprintf("unexpected argument %q", pos[0])}
		}
		rest = pos[1:]
	}

	cl := &cmdline{set: make(map[string]*rawValue)}
	fs.Visit(func(f *flag.Flag) {
		if v, ok := values[f.Name]; ok {
			cl.set[f.Name] = v
		}
	})
	cl.config = cl.set["config"]
	delete(cl.set, "config")

	switch {
	case *help || *h:
		cl.help = true
		return cl, nil
	case *version:
		cl.version = true
		return cl, nil
	case flagErr != nil:
		return nil, usageFromFlagError(flagErr)
	}
	cl.command = CommandRun
	if name != "" {
		c, ok := commandByName(name)
		if !ok {
			return nil, &UsageError{Msg: fmt.Sprintf("unknown subcommand %q (valid: %s)", name, commandNames())}
		}
		cl.command = c
	}
	if usageErr != nil {
		return nil, usageErr
	}
	return cl, nil
}

// usageFromFlagError rewrites the messages of the flag package.
func usageFromFlagError(err error) *UsageError {
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		return &UsageError{Msg: fmt.Sprintf("unknown flag --%s", name)}
	}
	if name, ok := strings.CutPrefix(msg, "flag needs an argument: -"); ok {
		return &UsageError{Msg: fmt.Sprintf("flag --%s needs a value", name)}
	}
	return &UsageError{Msg: msg}
}

// leafType returns the Go type of the leaf with the given YAML key.
func leafType(key string) reflect.Type {
	var cfg Config
	if v, ok := leafMap(&cfg)[key]; ok {
		return v.Type()
	}
	panic("config: flag bound to unknown YAML key " + key)
}

// applyFlags writes the explicitly set flags over cfg and records them as the
// origin of the affected values.
func applyFlags(cfg *Config, cl *cmdline, origins map[string]origin) []*Error {
	byKey := leafMap(cfg)
	var errs []*Error
	for _, spec := range flagSpecs {
		rv, ok := cl.set[spec.Name]
		if !ok {
			continue
		}
		if err := setFromFlag(byKey[spec.Key], "--"+spec.Name, rv.vals); err != nil {
			errs = append(errs, err)
			continue
		}
		forgetOrigins(origins, spec.Key)
		origins[spec.Key] = origin{flag: "--" + spec.Name}
	}
	return errs
}

// setFromFlag stores the occurrences of one flag in dst. A repeated scalar
// flag takes its last value; a list flag replaces the whole list.
func setFromFlag(dst reflect.Value, flagName string, vals []string) *Error {
	k, _ := kindOf(dst.Type())
	if k == kindList {
		if len(vals) == 1 && vals[0] == "" {
			dst.Set(reflect.MakeSlice(dst.Type(), 0, 0))
			return nil
		}
		if slices.Contains(vals, "") {
			return errorf(flagName, "an empty value cannot be combined with other values (a single empty value clears the list)")
		}
		dst.Set(reflect.ValueOf(slices.Clone(vals)))
		return nil
	}
	raw := vals[len(vals)-1]
	switch k {
	case kindString:
		dst.SetString(raw)
	case kindBool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return errorf(flagName, "invalid boolean value %q (use true or false)", raw)
		}
		dst.SetBool(b)
	case kindInt:
		n, err := strconv.Atoi(raw)
		switch {
		case errors.Is(err, strconv.ErrRange):
			return errorf(flagName, "integer value %q is out of range", raw)
		case err != nil:
			return errorf(flagName, "invalid integer value %q", raw)
		}
		dst.SetInt(int64(n))
	case kindDuration:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return errorf(flagName, "invalid duration %q (use Go syntax such as 500ms, 5s or 1m30s)", raw)
		}
		dst.SetInt(int64(d))
	}
	return nil
}

// origin says where a configuration value came from.
type origin struct {
	file string
	line int
	flag string
}

// forgetOrigins drops the origins of a key and of its list elements.
func forgetOrigins(m map[string]origin, key string) {
	for k := range m {
		if k == key || strings.HasPrefix(k, key+"[") {
			delete(m, k)
		}
	}
}
