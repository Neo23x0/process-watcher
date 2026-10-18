package config

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

const cfgPath = "/work/" + DefaultFileName

// anyLine marks syntax errors, whose line is chosen by the YAML parser.
const anyLine = -1

// base is a valid document of three lines; further lines start at line 4.
const base = "config_version: 1\nwatch:\n  image_contains: [nginx]\n"

type wantErr struct {
	path string
	line int
	msg  string // fragment
}

var yamlErrorCases = []struct {
	name string
	doc  string
	want []wantErr
}{
	// unknown keys
	{"unknown top level key", base + "foo: 1\n",
		[]wantErr{{"foo", 4, "valid keys: config_version, watch, exclude, capture, kill, outputs, delivery, runtime"}}},
	{"unknown nested key", base + "  image_contain: [x]\n",
		[]wantErr{{"watch.image_contain", 4, "valid keys: image_contains, ignore_case, max_depth"}}},
	{"unknown key in a deep section", base + "outputs:\n  file:\n    pth: x\n",
		[]wantErr{{"outputs.file.pth", 6, "unknown key"}}},
	{"flag style key", base + "capture:\n  capture-argv: true\n",
		[]wantErr{{"capture.capture-argv", 5, "unknown key"}}},
	{"key case matters", base + "Capture:\n  argv: true\n",
		[]wantErr{{"Capture", 4, "unknown key"}}},

	// duplicate keys
	{"duplicate top level section", "config_version: 1\nwatch:\n  image_contains: [nginx]\nwatch:\n  image_contains: [apache]\n",
		[]wantErr{{"watch", 4, "duplicate key (first defined on line 2)"}}},
	{"duplicate nested key", base + "  image_contains: [apache]\n",
		[]wantErr{{"watch.image_contains", 4, "duplicate key (first defined on line 3)"}}},
	{"duplicate scalar", base + "  max_depth: 1\n  max_depth: 2\n",
		[]wantErr{{"watch.max_depth", 5, "first defined on line 4"}}},
	{"duplicate config_version", "config_version: 1\nconfig_version: 1\n",
		[]wantErr{{"config_version", 2, "duplicate key"}}},
	{"duplicate in flow mapping", "config_version: 1\nwatch: {image_contains: [a], image_contains: [b]}\n",
		[]wantErr{{"watch.image_contains", 2, "duplicate key"}}},

	// wrong types
	{"string for integer", base + "  max_depth: \"3\"\n",
		[]wantErr{{"watch.max_depth", 4, "must be an integer, got a string"}}},
	{"float for integer", base + "  max_depth: 1.5\n",
		[]wantErr{{"watch.max_depth", 4, "must be an integer, got a number"}}},
	{"huge number for integer", base + "  max_depth: 99999999999999999999\n",
		[]wantErr{{"watch.max_depth", 4, "must be an integer, got a number"}}},
	{"integer out of range", base + "  max_depth: 18446744073709551615\n",
		[]wantErr{{"watch.max_depth", 4, "out of range"}}},
	{"null integer", base + "  max_depth:\n",
		[]wantErr{{"watch.max_depth", 4, "got an empty value"}}},
	{"string for boolean", base + "  ignore_case: \"true\"\n",
		[]wantErr{{"watch.ignore_case", 4, "must be a boolean (true or false), got a string"}}},
	{"yes is not a boolean", base + "  ignore_case: yes\n",
		[]wantErr{{"watch.ignore_case", 4, "must be a boolean"}}},
	{"on is not a boolean", base + "capture:\n  argv: on\n",
		[]wantErr{{"capture.argv", 5, "must be a boolean"}}},
	{"integer for boolean", base + "capture:\n  argv: 1\n",
		[]wantErr{{"capture.argv", 5, "got an integer"}}},
	{"integer for string", base + "outputs:\n  file:\n    path: 123\n",
		[]wantErr{{"outputs.file.path", 6, "must be a string, got an integer; put quotes"}}},
	{"boolean for string", base + "exclude:\n  scope: true\n",
		[]wantErr{{"exclude.scope", 5, "must be a string, got a boolean"}}},
	{"null string", base + "outputs:\n  tcp:\n    address:\n",
		[]wantErr{{"outputs.tcp.address", 6, `got an empty value; write ""`}}},
	{"list for string", base + "outputs:\n  tcp:\n    address: [a]\n",
		[]wantErr{{"outputs.tcp.address", 6, "must be a string, got a list"}}},
	{"mapping for list", base + "kill:\n  strings: {a: b}\n",
		[]wantErr{{"kill.strings", 5, "must be a list, got a mapping"}}},
	{"string for list", "config_version: 1\nwatch:\n  image_contains: nginx\n",
		[]wantErr{{"watch.image_contains", 3, "must be a list, got a string"}}},
	{"null list", "config_version: 1\nwatch:\n  image_contains:\n",
		[]wantErr{{"watch.image_contains", 3, "write []"}}},
	{"list for section", "config_version: 1\nwatch: [nginx]\n",
		[]wantErr{{"watch", 2, "must be a mapping of settings, got a list"}}},
	{"null section", base + "exclude:\n",
		[]wantErr{{"exclude", 4, "must be a mapping of settings, got an empty value"}}},
	{"null element in flow list", "config_version: 1\nwatch:\n  image_contains: [a, ~, b]\n",
		[]wantErr{{"watch.image_contains[1]", 3, "must not be empty"}}},
	{"null word element", "config_version: 1\nwatch:\n  image_contains: [null]\n",
		[]wantErr{{"watch.image_contains[0]", 3, "must not be empty"}}},
	{"empty block list element", "config_version: 1\nwatch:\n  image_contains:\n    - a\n    -\n    - b\n",
		[]wantErr{{"watch.image_contains[1]", 5, "must not be empty"}}},
	{"integer list element", "config_version: 1\nwatch:\n  image_contains: [a, 5]\n",
		[]wantErr{{"watch.image_contains[1]", 3, "must be a string, got an integer; put quotes"}}},
	{"nested list element", "config_version: 1\nwatch:\n  image_contains: [a, [b]]\n",
		[]wantErr{{"watch.image_contains[1]", 3, "got a list"}}},
	{"mapping list element", "config_version: 1\nwatch:\n  image_contains: [a, {x: y}]\n",
		[]wantErr{{"watch.image_contains[1]", 3, "got a mapping"}}},
	{"integer duration", base + "outputs:\n  file:\n    sync_interval: 5\n",
		[]wantErr{{"outputs.file.sync_interval", 6, "a bare number has no unit"}}},
	{"float duration", base + "outputs:\n  file:\n    sync_interval: 1.5\n",
		[]wantErr{{"outputs.file.sync_interval", 6, "a bare number has no unit"}}},
	{"invalid duration", base + "outputs:\n  file:\n    sync_interval: 5x\n",
		[]wantErr{{"outputs.file.sync_interval", 6, `invalid duration "5x"`}}},
	{"empty duration", base + "outputs:\n  file:\n    sync_interval: \"\"\n",
		[]wantErr{{"outputs.file.sync_interval", 6, "invalid duration"}}},
	{"timestamp for string", base + "outputs:\n  file:\n    path: 2001-12-14\n",
		[]wantErr{{"outputs.file.path", 6, "must be a string, got a timestamp"}}},
	{"binary for string", base + "outputs:\n  file:\n    path: !!binary aGVsbG8=\n",
		[]wantErr{{"outputs.file.path", 6, "binary data"}}},
	{"custom tag", base + "outputs:\n  file:\n    path: !secret x\n",
		[]wantErr{{"outputs.file.path", 6, "!secret"}}},

	// config_version
	{"config_version missing", "watch:\n  image_contains: [nginx]\n",
		[]wantErr{{"config_version", 1, "is required"}}},
	{"config_version wrong value", "config_version: 2\nwatch:\n  image_contains: [nginx]\n",
		[]wantErr{{"config_version", 1, "unsupported version 2"}}},
	{"config_version zero", "config_version: 0\n",
		[]wantErr{{"config_version", 1, "unsupported version 0"}}},
	{"config_version string", "config_version: \"1\"\n",
		[]wantErr{{"config_version", 1, "must be an integer, got a string"}}},
	{"config_version float", "config_version: 1.0\n",
		[]wantErr{{"config_version", 1, "got a number"}}},
	{"config_version null", "config_version:\n",
		[]wantErr{{"config_version", 1, "got an empty value"}}},
	{"empty mapping", "{}\n",
		[]wantErr{{"config_version", 1, "is required"}}},

	// whole file problems
	{"empty file", "", []wantErr{{"", 0, "the file is empty"}}},
	{"blank file", "\n\n", []wantErr{{"", 0, "the file is empty"}}},
	{"comment only", "# nothing here\n", []wantErr{{"", 0, "the file is empty"}}},
	{"document marker only", "---\n", []wantErr{{"", 2, "no settings"}}},
	{"null document", "~\n", []wantErr{{"", 1, "no settings"}}},
	{"multiple documents", "config_version: 1\n---\nconfig_version: 1\n",
		[]wantErr{{"", 2, "multiple YAML documents"}}},
	{"trailing document marker", base + "---\n",
		[]wantErr{{"", 4, "multiple YAML documents"}}},
	{"syntax error in second document", base + "---\n: [\n",
		[]wantErr{{"", anyLine, "invalid YAML"}}},
	{"flow list not closed", "watch: [a\n", []wantErr{{"", 1, "invalid YAML"}}},
	{"tab indentation", "config_version: 1\nwatch:\n\timage_contains: [a]\n", []wantErr{{"", 3, "invalid YAML"}}},
	{"bad indentation", "config_version: 1\nwatch:\n  image_contains: [a]\n max_depth: 1\n", []wantErr{{"", anyLine, "invalid YAML"}}},
	{"unterminated quote", "config_version: 1\nwatch:\n  image_contains: [\"a]\n", []wantErr{{"", anyLine, "invalid YAML"}}},
	{"invalid utf-8", "config_version: 1\nwatch:\n  image_contains: [\"a\xff\"]\n", []wantErr{{"", 0, "invalid YAML"}}},
	{"top level list", "- a\n- b\n", []wantErr{{"", 1, "must be a mapping of settings, got a list"}}},
	{"top level scalar", "hello\n", []wantErr{{"", 1, "must be a mapping of settings, got a string"}}},
	{"complex key", base + "? [a]\n: 1\n", []wantErr{{"", 4, "mapping keys must be plain strings"}}},

	// features that are deliberately unsupported
	{"alias", "config_version: 1\nwatch:\n  image_contains: &names [nginx]\nexclude:\n  image_contains: *names\n",
		[]wantErr{{"exclude.image_contains", 5, "aliases are not supported"}}},
	{"alias in list", "config_version: 1\nwatch:\n  image_contains: [&n nginx, *n]\n",
		[]wantErr{{"watch.image_contains[1]", 3, "aliases are not supported"}}},
	{"merge key", "config_version: 1\nwatch: &w\n  image_contains: [nginx]\nexclude:\n  <<: *w\n",
		[]wantErr{{"exclude", 5, "merge keys"}}},

	// all problems of a file are reported
	{"several problems", "config_version: 1\nfoo: 1\nwatch:\n  max_depth: x\n  image_contains: nginx\nbar: 2\n",
		[]wantErr{{"foo", 2, "unknown key"}, {"watch.max_depth", 4, "must be an integer"}, {"watch.image_contains", 5, "must be a list"}, {"bar", 6, "unknown key"}}},
}

func TestYAMLErrors(t *testing.T) {
	for _, tc := range yamlErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newFakeEnv().cwdFile(tc.doc)
			r, err := Resolve([]string{"check-config"}, env.Env())
			if err == nil {
				t.Fatalf("document accepted, want %v\n%s", tc.want, tc.doc)
			}
			if r != nil {
				t.Errorf("non-nil result together with an error")
			}
			errs := flatten(err)
			if len(errs) != len(tc.want) {
				t.Fatalf("got %d errors, want %d:\n%v", len(errs), len(tc.want), err)
			}
			for i, w := range tc.want {
				e := errs[i]
				lineOK := e.Line == w.line || (w.line == anyLine && e.Line > 0)
				if e.Path != w.path || !lineOK || e.File != cfgPath {
					t.Errorf("error %d = {path %q, line %d, file %q}, want {path %q, line %d, file %q}\n%v",
						i, e.Path, e.Line, e.File, w.path, w.line, cfgPath, e)
				}
				if !strings.Contains(e.Error(), w.msg) {
					t.Errorf("error %d %q does not contain %q", i, e, w.msg)
				}
				if !strings.Contains(e.Error(), cfgPath) {
					t.Errorf("error %d %q does not name the file", i, e)
				}
				if want := ":" + strconv.Itoa(e.Line); e.Line > 0 && !strings.Contains(e.Error(), want) {
					t.Errorf("error %d %q does not name its line", i, e)
				}
			}
		})
	}
}

func TestYAMLAccepted(t *testing.T) {
	tests := []struct {
		name  string
		doc   string
		check func(t *testing.T, c Config)
	}{
		{"minimal", base, func(t *testing.T, c Config) {
			if !reflect.DeepEqual(c.Watch.ImageContains, []string{"nginx"}) {
				t.Errorf("watch = %v", c.Watch.ImageContains)
			}
		}},
		{"explicit document markers", "---\n" + base + "...\n", nil},
		{"crlf line endings", strings.ReplaceAll(base, "\n", "\r\n"), nil},
		{"byte order mark", "\xef\xbb\xbf" + base, nil},
		{"comments and blank lines", "# comment\n\nconfig_version: 1 # trailing\n\nwatch:\n  # inner\n  image_contains: [nginx]\n", nil},
		{"unused anchor", "config_version: 1\nwatch: &w\n  image_contains: [nginx]\n", nil},
		{"same key in different sections", "config_version: 1\nwatch:\n  image_contains: [a]\nexclude:\n  image_contains: [b]\nkill:\n  strings: [c]\n",
			func(t *testing.T, c Config) {
				if c.Watch.ImageContains[0] != "a" || c.Exclude.ImageContains[0] != "b" {
					t.Errorf("lists mixed up: %+v", c)
				}
			}},
		{"quoted strings", base + "exclude:\n  scope: \"all\"\noutputs:\n  file:\n    path: 'x.jsonl'\n",
			func(t *testing.T, c Config) {
				if c.Exclude.Scope != ScopeAll || c.Outputs.File.Path != "/work/x.jsonl" {
					t.Errorf("got %q and %q", c.Exclude.Scope, c.Outputs.File.Path)
				}
			}},
		{"tagged string keeps number text", base + "outputs:\n  file:\n    path: !!str 123\n",
			func(t *testing.T, c Config) {
				if c.Outputs.File.Path != "/work/123" {
					t.Errorf("path = %q", c.Outputs.File.Path)
				}
			}},
		{"block list", "config_version: 1\nwatch:\n  image_contains:\n    - a\n    - b\n",
			func(t *testing.T, c Config) {
				if !reflect.DeepEqual(c.Watch.ImageContains, []string{"a", "b"}) {
					t.Errorf("watch = %v", c.Watch.ImageContains)
				}
			}},
		{"hex integer", base + "  max_depth: 0x10\n", func(t *testing.T, c Config) {
			if c.Watch.MaxDepth != 16 {
				t.Errorf("max_depth = %d", c.Watch.MaxDepth)
			}
		}},
		{"duration spellings", base + "outputs:\n  file:\n    sync_interval: 1m30s\n  webhook:\n    timeout: 250ms\n",
			func(t *testing.T, c Config) {
				if c.Outputs.File.SyncInterval != 90*time.Second || c.Outputs.Webhook.Timeout != 250*time.Millisecond {
					t.Errorf("durations = %v, %v", c.Outputs.File.SyncInterval, c.Outputs.Webhook.Timeout)
				}
			}},
		{"explicit empty lists replace defaults", base + "kill:\n  fields: [argv]\n  strings: []\nexclude:\n  image_contains: []\n",
			func(t *testing.T, c Config) {
				if !reflect.DeepEqual(c.Kill.Fields, []string{"argv"}) || c.Kill.Strings == nil || len(c.Kill.Strings) != 0 {
					t.Errorf("kill = %+v", c.Kill)
				}
			}},
		{"empty flow mapping section", base + "exclude: {}\n", nil},
		{"duplicate list entries", base + "kill:\n  fields: [image, image]\n  strings: [x, x]\n", func(t *testing.T, c Config) {
			if len(c.Kill.Fields) != 2 || len(c.Kill.Strings) != 2 {
				t.Errorf("duplicates were dropped: %+v", c.Kill)
			}
		}},
		{"unicode strings", "config_version: 1\nwatch:\n  image_contains: [\"gr\u00fc\u00dfe\", \"\\u00e9\"]\n", func(t *testing.T, c Config) {
			if !reflect.DeepEqual(c.Watch.ImageContains, []string{"gr\u00fc\u00dfe", "\u00e9"}) {
				t.Errorf("watch = %q", c.Watch.ImageContains)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newFakeEnv().cwdFile(tc.doc)
			r, err := Resolve([]string{"check-config"}, env.Env())
			if err != nil {
				t.Fatalf("document rejected: %v\n%s", err, tc.doc)
			}
			if r.SourceFile != cfgPath {
				t.Errorf("SourceFile = %q", r.SourceFile)
			}
			if tc.check != nil {
				tc.check(t, r.Config)
			}
		})
	}
}

func TestYAMLWithoutKeysKeepsDefaults(t *testing.T) {
	env := newFakeEnv().cwdFile(base)
	r := mustResolve(t, env)
	want := Default()
	want.Watch.ImageContains = []string{"nginx"}
	want.Outputs.File.Path = "/work/process-watcher.jsonl"
	if !reflect.DeepEqual(r.Config, want) {
		t.Errorf("config = %+v\nwant     %+v", r.Config, want)
	}
}

// The examples of the specifications must load as documented.
func TestSpecExamplesLoad(t *testing.T) {
	buildSpec := `config_version: 1

watch:
  image_contains: ["nginx"]
  ignore_case: false
  max_depth: 0

exclude:
  image_contains: []
  argv_contains: []
  scope: remote

capture:
  argv: false
  argv_max_args: 32
  argv_max_bytes: 4096

outputs:
  file:
    path: ./process-watcher.jsonl
    rotate_size_mb: 100
    keep_files: 5
    sync_interval: 1s
  tcp:
    address: ""
    tls: false
    ca_file: ""
    server_name: ""
  udp:
    address: ""
    max_bytes: 8192
  webhook:
    url: ""
    token_env: ""
    timeout: 10s

delivery:
  queue_size: 10000
  connect_timeout: 5s
  write_timeout: 5s
  max_retries: 5

runtime:
  ring_buffer_mb: 16
  max_processes: 65536
  health_interval: 60s
  reconcile_interval: 30s
  shutdown_timeout: 10s
`
	r := mustResolve(t, newFakeEnv().cwdFile(buildSpec))
	want := Default()
	want.Watch.ImageContains = []string{"nginx"}
	want.Outputs.File.Path = "/work/process-watcher.jsonl"
	if !reflect.DeepEqual(r.Config, want) {
		t.Errorf("the documented example differs from the defaults:\n got %+v\nwant %+v", r.Config, want)
	}

	killSpec := `config_version: 1
watch:
  image_contains: [nginx]

capture:
  argv: true

kill:
  enabled: true
  dry_run: false
  fields: [image, argv]
  strings:
    - demo-long-running-helper
  regex:
    - '^(useradd|usermod)$'

outputs:
  file:
    path: ./process-watcher.jsonl
`
	r = mustResolve(t, newFakeEnv().cwdFile(killSpec))
	k := r.Config.Kill
	if !k.Enabled || k.DryRun || !r.Config.Capture.Argv ||
		!reflect.DeepEqual(k.Fields, []string{"image", "argv"}) ||
		!reflect.DeepEqual(k.Strings, []string{"demo-long-running-helper"}) ||
		!reflect.DeepEqual(k.Regex, []string{"^(useradd|usermod)$"}) {
		t.Errorf("kill example loaded as %+v (argv capture %v)", k, r.Config.Capture.Argv)
	}

	defaults := "kill:\n  enabled: false\n  dry_run: false\n  fields: [image]\n  strings: []\n  regex: []\n"
	r = mustResolve(t, newFakeEnv().cwdFile(base+defaults))
	if !reflect.DeepEqual(r.Config.Kill, Default().Kill) {
		t.Errorf("kill defaults loaded as %+v", r.Config.Kill)
	}
}

// Validation errors of values from a YAML file carry the file and line.
func TestYAMLValidationErrorsCarryLines(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		path string
		line int
		msg  string
	}{
		{"kill field in flow list", "config_version: 1\nwatch:\n  image_contains: [nginx]\nkill:\n  enabled: true\n  fields: [image, bogus]\n  strings: [x]\n",
			"kill.fields[1]", 6, `unknown field "bogus"`},
		{"kill regex in block list", "config_version: 1\nwatch:\n  image_contains: [nginx]\nkill:\n  regex:\n    - ok\n    - '('\n",
			"kill.regex[1]", 7, "invalid regular expression"},
		{"kill regex index two", "config_version: 1\nwatch:\n  image_contains: [nginx]\nkill:\n  regex: [a, b, '(c']\n",
			"kill.regex[2]", 5, "missing closing )"},
		{"empty watch entry", "config_version: 1\nwatch:\n  image_contains:\n    - nginx\n    - \"\"\n",
			"watch.image_contains[1]", 5, "must not be empty"},
		{"empty kill string", base + "kill:\n  strings: [\"\"]\n",
			"kill.strings[0]", 5, "must not be empty"},
		{"scope", base + "exclude:\n  scope: nope\n", "exclude.scope", 5, `"remote" or "all"`},
		{"negative depth", base + "  max_depth: -3\n", "watch.max_depth", 4, "got -3"},
		{"empty watch list", "config_version: 1\nwatch:\n  image_contains: []\n", "watch.image_contains", 3, "at least one pattern"},
		{"argv field needs capture", base + "kill:\n  enabled: true\n  fields: [argv]\n  strings: [x]\n", "kill.fields[0]", 6, "capture.argv: true"},
		{"exclude argv needs capture", base + "exclude:\n  argv_contains: [x]\n", "exclude.argv_contains", 5, "capture.argv: true"},
		{"udp size", base + "outputs:\n  udp:\n    max_bytes: 100\n", "outputs.udp.max_bytes", 6, "between 512 and 65507"},
		{"ring buffer", base + "runtime:\n  ring_buffer_mb: 3\n", "runtime.ring_buffer_mb", 5, "power of two"},
		{"webhook url", base + "outputs:\n  webhook:\n    url: ftp://x.example/y\n", "outputs.webhook.url", 6, "http or https"},
		{"sync interval", base + "outputs:\n  file:\n    sync_interval: 0s\n", "outputs.file.sync_interval", 6, "positive duration"},
		{"kill enabled", base + "kill:\n  enabled: true\n", "kill.enabled", 5, "at least one rule"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := resolveErrors(t, newFakeEnv().cwdFile(tc.doc), "check-config")
			e := wantOneError(t, errs, tc.path, tc.msg)
			if e.File != cfgPath || e.Line != tc.line || e.Flag != "" {
				t.Errorf("origin = {%q, %d, %q}, want {%q, %d, \"\"}", e.File, e.Line, e.Flag, cfgPath, tc.line)
			}
			if want := cfgPath + ":" + strconv.Itoa(tc.line) + ": " + tc.path + ": "; !strings.HasPrefix(e.Error(), want) {
				t.Errorf("error %q does not start with %q", e, want)
			}
		})
	}
}

// A value replaced by a flag is reported with the flag, not the stale line.
func TestFlagOriginWinsOverYAMLLine(t *testing.T) {
	env := newFakeEnv().cwdFile(base + "outputs:\n  udp:\n    max_bytes: 100\n")
	// The YAML value is invalid but the flag fixes it.
	mustResolve(t, env, "--udp-max-bytes", "600")

	// The flag value is invalid and is reported as such.
	errs := resolveErrors(t, env, "--udp-max-bytes", "200")
	e := wantOneError(t, errs, "outputs.udp.max_bytes", "set by flag --udp-max-bytes")
	if e.File != "" || e.Line != 0 || e.Flag != "--udp-max-bytes" {
		t.Errorf("origin = {%q, %d, %q}", e.File, e.Line, e.Flag)
	}

	// An invalid list element from YAML loses its line once the flag
	// replaces the list.
	env = newFakeEnv().cwdFile(base + "kill:\n  regex: [a, '(']\n")
	errs = resolveErrors(t, env)
	wantOneError(t, errs, "kill.regex[1]", cfgPath+":5")
	errs = resolveErrors(t, env, "--kill-regex", "x", "--kill-regex", ")")
	e = wantOneError(t, errs, "kill.regex[1]", "set by flag --kill-regex")
	if e.File != "" {
		t.Errorf("stale file origin %q after the flag replaced the list", e.File)
	}
}

// The final decode is a safety net behind the schema check; its errors are
// still reported as *Error values.
func TestDecodeErrorSafetyNet(t *testing.T) {
	c := &yamlChecker{file: cfgPath, origins: map[string]origin{}}
	dec := yaml.NewDecoder(strings.NewReader("config_version: 1\nwatch:\n  nope: 1\n"))
	dec.KnownFields(true)
	cfg := Default()
	err := dec.Decode(&cfg)
	if err == nil {
		t.Fatal("the YAML decoder accepted an unknown field")
	}
	c.decodeError(err)
	if len(c.errs) != 1 || c.errs[0].Line != 3 || c.errs[0].File != cfgPath || !strings.Contains(c.errs[0].Msg, "nope") {
		t.Errorf("errors = %v", c.errs)
	}

	c = &yamlChecker{file: cfgPath, origins: map[string]origin{}}
	c.decodeError(errors.New("yaml: line 7: broken"))
	if len(c.errs) != 1 || c.errs[0].Line != 7 || !strings.Contains(c.errs[0].Msg, "broken") {
		t.Errorf("errors = %v", c.errs)
	}
}
