package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDefaultsResolve(t *testing.T) {
	env := newFakeEnv()
	r := mustResolve(t, env, withWatch()...)
	want := Default()
	want.Watch.ImageContains = []string{"nginx"}
	want.Outputs.File.Path = "/work/process-watcher.jsonl"
	if !reflect.DeepEqual(r.Config, want) {
		t.Errorf("config = %+v\nwant     %+v", r.Config, want)
	}
	if r.Command != CommandRun || r.SourceFile != "" || r.Cwd != "/work" {
		t.Errorf("result = {%q, %q, %q}, want run, no source file, /work", r.Command, r.SourceFile, r.Cwd)
	}
	if len(env.envKeys) != 0 {
		t.Errorf("Resolve read environment variables %v without a webhook token", env.envKeys)
	}

	// The documented defaults.
	c := r.Config
	if c.Watch.IgnoreCase || c.Watch.MaxDepth != 0 || c.Exclude.Scope != ScopeRemote || c.Capture.Argv ||
		c.Kill.Enabled || c.Kill.DryRun || !reflect.DeepEqual(c.Kill.Fields, []string{"image"}) ||
		c.Outputs.File.RotateSizeMB != 100 || c.Outputs.File.KeepFiles != 5 || c.Outputs.File.SyncInterval != time.Second ||
		c.Outputs.TCP.Address != "" || c.Outputs.UDP.MaxBytes != 8192 || c.Outputs.Webhook.Timeout != 10*time.Second ||
		c.Delivery.QueueSize != 10000 || c.Delivery.ConnectTimeout != 5*time.Second || c.Delivery.WriteTimeout != 5*time.Second ||
		c.Delivery.MaxRetries != 5 || c.Runtime.RingBufferMB != 16 || c.Runtime.MaxProcesses != 65536 ||
		c.Runtime.HealthInterval != 60*time.Second || c.Runtime.ReconcileInterval != 30*time.Second ||
		c.Runtime.ShutdownTimeout != 10*time.Second {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestListsAreNeverNil(t *testing.T) {
	r := mustResolve(t, newFakeEnv(), withWatch("--exclude-image-contains=", "--kill-string=")...)
	for _, l := range leaves(&r.Config) {
		if l.Val.Kind() == reflect.Slice && l.Val.IsNil() {
			t.Errorf("%s is nil", l.Key)
		}
	}
}

func TestCommands(t *testing.T) {
	tests := []struct {
		args []string
		want Command
	}{
		{withWatch(), CommandRun},
		{withWatch("run"), CommandRun},
		{withWatch("check-config"), CommandCheckConfig},
		{withWatch("print-config"), CommandPrintConfig},
		{withWatch("doctor"), CommandDoctor},
		{[]string{"run", "--watch-image-contains", "nginx"}, CommandRun},
		{[]string{"check-config", "--watch-image-contains", "nginx"}, CommandCheckConfig},
		{[]string{"--watch-image-contains", "nginx", "print-config", "--capture-argv"}, CommandPrintConfig},
		{[]string{"--capture-argv", "check-config", "--watch-image-contains=nginx"}, CommandCheckConfig},
		{[]string{"-watch-image-contains", "nginx", "-capture-argv=true"}, CommandRun},
		{[]string{"doctor"}, CommandDoctor},
	}
	for _, tc := range tests {
		r := mustResolve(t, newFakeEnv(), tc.args...)
		if r.Command != tc.want {
			t.Errorf("Resolve(%q).Command = %q, want %q", tc.args, r.Command, tc.want)
		}
	}
	// Flags before and after the subcommand are all applied.
	r := mustResolve(t, newFakeEnv(), "--capture-argv", "check-config", "--watch-image-contains", "nginx", "--log-keep-files", "2")
	if !r.Config.Capture.Argv || r.Config.Outputs.File.KeepFiles != 2 {
		t.Errorf("flags around the subcommand were not all applied: %+v", r.Config)
	}
}

func TestHelpAndVersion(t *testing.T) {
	tests := []struct {
		args []string
		want Command
	}{
		{[]string{"--help"}, CommandHelp},
		{[]string{"-h"}, CommandHelp},
		{[]string{"-help"}, CommandHelp},
		{[]string{"run", "--help"}, CommandHelp},
		{[]string{"--help", "run"}, CommandHelp},
		{[]string{"check-config", "-h"}, CommandHelp},
		{[]string{"doctor", "--watch-max-depth", "-1", "-h"}, CommandHelp},
		{[]string{"--help", "--bogus"}, CommandHelp},
		{[]string{"bogus", "--help"}, CommandHelp},
		{[]string{"run", "extra", "--help"}, CommandHelp},
		{[]string{"--help", "--version"}, CommandHelp},
		{[]string{"--version"}, CommandVersion},
		{[]string{"run", "--version"}, CommandVersion},
		{[]string{"--version", "--bogus"}, CommandVersion},
	}
	for _, tc := range tests {
		// The environment holds a broken configuration file that must not be read.
		env := newFakeEnv().cwdFile("not: [valid")
		r, err := Resolve(tc.args, env.Env())
		if err != nil {
			t.Errorf("Resolve(%q) failed: %v", tc.args, err)
			continue
		}
		if r.Command != tc.want {
			t.Errorf("Resolve(%q).Command = %q, want %q", tc.args, r.Command, tc.want)
		}
		if len(env.stats)+len(env.reads) != 0 {
			t.Errorf("Resolve(%q) touched the file system", tc.args)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"bogus"}, `unknown subcommand "bogus" (valid: run, check-config, print-config, doctor)`},
		{[]string{"help"}, `unknown subcommand "help"`},
		{[]string{"version"}, `unknown subcommand "version"`},
		{[]string{"-"}, `unknown subcommand "-"`},
		{[]string{"RUN"}, `unknown subcommand "RUN"`},
		{[]string{"--bogus"}, "unknown flag --bogus"},
		{[]string{"-bogus=1"}, "unknown flag --bogus"},
		{[]string{"run", "--no-such-flag", "x"}, "unknown flag --no-such-flag"},
		{[]string{"--watch_image_contains", "x"}, "unknown flag --watch_image_contains"},
		{[]string{"--log-file"}, "flag --log-file needs a value"},
		{[]string{"--config"}, "flag --config needs a value"},
		{[]string{"run", "extra"}, `unexpected argument "extra"`},
		{[]string{"run", "check-config"}, `unexpected argument "check-config"`},
		{[]string{"check-config", "run", "x"}, `unexpected argument "run"`},
		{[]string{"--capture-argv", "false"}, `unknown subcommand "false"`},
		{[]string{"---x"}, "bad flag syntax"},
		{[]string{"--=x"}, "bad flag syntax"},
		{[]string{"--watch-image-contains", "nginx", "run", "--", "x"}, `unexpected argument "x"`},
		{[]string{"--version=x", "--bogus"}, "invalid boolean"},
	}
	for _, tc := range tests {
		r, err := Resolve(tc.args, newFakeEnv().Env())
		if err == nil {
			t.Errorf("Resolve(%q) succeeded with %+v, want a usage error", tc.args, r)
			continue
		}
		var ue *UsageError
		if !errors.As(err, &ue) {
			t.Errorf("Resolve(%q) returned %T %v, want *UsageError", tc.args, err, err)
			continue
		}
		if !strings.Contains(ue.Error(), tc.want) {
			t.Errorf("Resolve(%q) error = %q, want it to contain %q", tc.args, ue, tc.want)
		}
		var ce *Error
		if errors.As(err, &ce) {
			t.Errorf("Resolve(%q) usage error is also a *Error", tc.args)
		}
	}
}

func TestFlagValueErrorsNameTheFlag(t *testing.T) {
	tests := []struct {
		args []string
		path string
		msg  string
	}{
		{[]string{"--log-rotate-size-mb", "abc"}, "--log-rotate-size-mb", `invalid integer value "abc"`},
		{[]string{"--max-retries=1.5"}, "--max-retries", "invalid integer"},
		{[]string{"--queue-size", ""}, "--queue-size", "invalid integer"},
		{[]string{"--queue-size", "99999999999999999999"}, "--queue-size", "out of range"},
		{[]string{"--log-sync-interval", "5"}, "--log-sync-interval", "invalid duration"},
		{[]string{"--health-interval", "fast"}, "--health-interval", "Go syntax"},
		{[]string{"--webhook-timeout="}, "--webhook-timeout", "invalid duration"},
		{[]string{"--capture-argv=maybe"}, "--capture-argv", "use true or false"},
		{[]string{"--watch-ignore-case=2"}, "--watch-ignore-case", "invalid boolean"},
		{[]string{"--tcp-tls="}, "--tcp-tls", "invalid boolean"},
		{[]string{"--exclude-image-contains", "a", "--exclude-image-contains="}, "--exclude-image-contains", "empty value cannot be combined"},
		{[]string{"--kill-regex=", "--kill-regex", "x"}, "--kill-regex", "single empty value clears the list"},
		{[]string{"--kill-field", "", "--kill-field", "image"}, "--kill-field", "empty value cannot be combined"},
		{[]string{"--config="}, "--config", "must not be empty"},
	}
	for _, tc := range tests {
		errs := resolveErrors(t, newFakeEnv(), withWatch(tc.args...)...)
		e := wantOneError(t, errs, tc.path, tc.msg)
		if e.File != "" || e.Flag != "" || e.Line != 0 {
			t.Errorf("%q: pure command line problem carries an origin: %#v", tc.args, e)
		}
	}

	// All command line problems are reported together.
	errs := resolveErrors(t, newFakeEnv(), withWatch("--max-retries=x", "--log-keep-files", "y")...)
	if got := paths(errs); !reflect.DeepEqual(got, []string{"--log-keep-files", "--max-retries"}) && !reflect.DeepEqual(got, []string{"--max-retries", "--log-keep-files"}) {
		t.Errorf("paths = %q, want both flags", got)
	}
}

func TestFlagsOverrideYAML(t *testing.T) {
	yamlDoc := `config_version: 1
watch:
  image_contains: [from-yaml, second-yaml]
  ignore_case: true
  max_depth: 4
exclude:
  image_contains: [yaml-helper]
  argv_contains: [--yaml-secret]
  scope: all
capture:
  argv: true
kill:
  enabled: true
  dry_run: true
  fields: [image, argv]
  strings: [yaml-string]
  regex: ['^yaml$']
outputs:
  file:
    path: /yaml/events.jsonl
    rotate_size_mb: 50
    keep_files: 3
    sync_interval: 2s
  tcp:
    address: yaml.example:9000
    tls: true
    ca_file: /yaml/ca.pem
    server_name: yaml.example
  udp:
    address: yaml.example:9001
    max_bytes: 1000
  webhook:
    url: https://yaml.example/hook
    token_env: YAML_TOKEN
    timeout: 20s
delivery:
  queue_size: 100
  connect_timeout: 1s
  write_timeout: 2s
  max_retries: 1
runtime:
  ring_buffer_mb: 4
  max_processes: 1000
  health_interval: 10s
  reconcile_interval: 11s
  shutdown_timeout: 12s
`
	env := newFakeEnv().cwdFile(yamlDoc)
	env.vars["YAML_TOKEN"] = "x"
	env.vars["FLAG_TOKEN"] = "y"

	// Without flags everything comes from the file.
	r := mustResolve(t, env)
	c := r.Config
	if !reflect.DeepEqual(c.Watch.ImageContains, []string{"from-yaml", "second-yaml"}) || !c.Watch.IgnoreCase || c.Watch.MaxDepth != 4 ||
		c.Exclude.Scope != ScopeAll || !c.Capture.Argv || !c.Kill.Enabled || !c.Kill.DryRun ||
		c.Outputs.File.Path != "/yaml/events.jsonl" || c.Outputs.File.RotateSizeMB != 50 || c.Outputs.TCP.Address != "yaml.example:9000" ||
		c.Outputs.UDP.MaxBytes != 1000 || c.Outputs.Webhook.Timeout != 20*time.Second || c.Delivery.QueueSize != 100 ||
		c.Runtime.RingBufferMB != 4 || c.Runtime.ShutdownTimeout != 12*time.Second {
		t.Fatalf("YAML values not applied: %+v", c)
	}

	// Explicitly set flags win, one of each kind; everything else stays.
	r = mustResolve(t, env,
		"--watch-image-contains", "from-flag", // list
		"--watch-ignore-case=false", // bool
		"--watch-max-depth", "0",    // int, equal to the default
		"--exclude-scope", "remote", // string, equal to the default
		"--log-sync-interval", "250ms", // duration
		"--webhook-token-env", "FLAG_TOKEN",
		"--tcp-address=", // explicit empty string
	)
	c = r.Config
	if !reflect.DeepEqual(c.Watch.ImageContains, []string{"from-flag"}) {
		t.Errorf("watch list = %v, want the flag to replace the YAML list", c.Watch.ImageContains)
	}
	if c.Watch.IgnoreCase || c.Watch.MaxDepth != 0 || c.Exclude.Scope != ScopeRemote {
		t.Errorf("flags equal to defaults did not override YAML: %+v", c.Watch)
	}
	if c.Outputs.File.SyncInterval != 250*time.Millisecond || c.Outputs.Webhook.TokenEnv != "FLAG_TOKEN" || c.Outputs.TCP.Address != "" {
		t.Errorf("flags did not override YAML: %+v", c.Outputs)
	}
	// Unset flags never override the file.
	if !c.Capture.Argv || !c.Kill.Enabled || c.Outputs.File.RotateSizeMB != 50 || c.Outputs.File.KeepFiles != 3 ||
		!reflect.DeepEqual(c.Exclude.ImageContains, []string{"yaml-helper"}) || !reflect.DeepEqual(c.Kill.Fields, []string{"image", "argv"}) ||
		c.Delivery.MaxRetries != 1 || c.Runtime.HealthInterval != 10*time.Second || !c.Outputs.TCP.TLS {
		t.Errorf("unset flags changed YAML values: %+v", c)
	}
}

func TestListFlagSemantics(t *testing.T) {
	yamlDoc := "config_version: 1\nwatch:\n  image_contains: [y1, y2]\nexclude:\n  image_contains: [e1]\n  argv_contains: [a1]\ncapture:\n  argv: true\nkill:\n  fields: [image, argv]\n  strings: [s1]\n  regex: [r1]\n"
	tests := []struct {
		name  string
		args  []string
		check func(c Config) bool
	}{
		{"one flag replaces the whole list", []string{"--exclude-image-contains", "x"},
			func(c Config) bool { return reflect.DeepEqual(c.Exclude.ImageContains, []string{"x"}) }},
		{"repeated flags keep order and duplicates", []string{"--exclude-image-contains", "b", "--exclude-image-contains", "a", "--exclude-image-contains", "b"},
			func(c Config) bool { return reflect.DeepEqual(c.Exclude.ImageContains, []string{"b", "a", "b"}) }},
		{"other lists are untouched", []string{"--exclude-image-contains", "x"},
			func(c Config) bool {
				return reflect.DeepEqual(c.Watch.ImageContains, []string{"y1", "y2"}) && reflect.DeepEqual(c.Exclude.ArgvContains, []string{"a1"})
			}},
		{"single empty value clears", []string{"--exclude-image-contains="},
			func(c Config) bool { return c.Exclude.ImageContains != nil && len(c.Exclude.ImageContains) == 0 }},
		{"single empty value as separate argument clears", []string{"--exclude-image-contains", ""},
			func(c Config) bool { return c.Exclude.ImageContains != nil && len(c.Exclude.ImageContains) == 0 }},
		{"clearing leaves other lists", []string{"--exclude-argv-contains="},
			func(c Config) bool {
				return len(c.Exclude.ArgvContains) == 0 && reflect.DeepEqual(c.Exclude.ImageContains, []string{"e1"})
			}},
		{"commas are literal", []string{"--exclude-image-contains", "a,b", "--exclude-image-contains", "c, d"},
			func(c Config) bool { return reflect.DeepEqual(c.Exclude.ImageContains, []string{"a,b", "c, d"}) }},
		{"kill fields replaced", []string{"--kill-field", "image_path"},
			func(c Config) bool { return reflect.DeepEqual(c.Kill.Fields, []string{"image_path"}) }},
		{"kill strings and regex are separate lists", []string{"--kill-string", "s2", "--kill-string", "s3"},
			func(c Config) bool {
				return reflect.DeepEqual(c.Kill.Strings, []string{"s2", "s3"}) && reflect.DeepEqual(c.Kill.Regex, []string{"r1"})
			}},
		{"whitespace is not empty", []string{"--exclude-image-contains", " "},
			func(c Config) bool { return reflect.DeepEqual(c.Exclude.ImageContains, []string{" "}) }},
		{"value starting with a dash", []string{"--kill-string", "-rf", "--kill-regex", "-x"},
			func(c Config) bool {
				return reflect.DeepEqual(c.Kill.Strings, []string{"-rf"}) && reflect.DeepEqual(c.Kill.Regex, []string{"-x"})
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mustResolve(t, newFakeEnv().cwdFile(yamlDoc), tc.args...)
			if !tc.check(r.Config) {
				t.Errorf("unexpected result for %q: %+v", tc.args, r.Config)
			}
		})
	}
}

func TestBoolFlags(t *testing.T) {
	withArgv := base + "capture:\n  argv: true\n"
	tests := []struct {
		name string
		doc  string
		args []string
		want bool
	}{
		{"default is false", base, nil, false},
		{"bare flag is true", base, []string{"--capture-argv"}, true},
		{"explicit true", base, []string{"--capture-argv=true"}, true},
		{"yaml true", withArgv, nil, true},
		{"explicit false overrides yaml", withArgv, []string{"--capture-argv=false"}, false},
		{"single dash false", withArgv, []string{"-capture-argv=false"}, false},
		{"bare flag keeps yaml true", withArgv, []string{"--capture-argv"}, true},
		{"1", base, []string{"--capture-argv=1"}, true},
		{"0 overrides yaml", withArgv, []string{"--capture-argv=0"}, false},
		{"TRUE", base, []string{"--capture-argv=TRUE"}, true},
		{"t", base, []string{"--capture-argv=t"}, true},
		{"F overrides yaml", withArgv, []string{"--capture-argv=F"}, false},
		{"last occurrence wins", base, []string{"--capture-argv=true", "--capture-argv=false"}, false},
		{"last occurrence wins again", withArgv, []string{"--capture-argv=false", "--capture-argv"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mustResolve(t, newFakeEnv().cwdFile(tc.doc), tc.args...)
			if r.Config.Capture.Argv != tc.want {
				t.Errorf("capture.argv = %v, want %v", r.Config.Capture.Argv, tc.want)
			}
		})
	}

	// The same for every other boolean flag.
	for _, name := range []string{"watch-ignore-case", "kill-enabled", "kill-dry-run", "tcp-tls"} {
		for _, val := range []string{"true", "false"} {
			cl, err := parseArgs([]string{"--" + name + "=" + val})
			if err != nil {
				t.Fatal(err)
			}
			cfg := Default()
			if errs := applyFlags(&cfg, cl, map[string]origin{}); len(errs) != 0 {
				t.Fatal(errs)
			}
			var got bool
			for _, s := range flagSpecs {
				if s.Name == name {
					got = leafMap(&cfg)[s.Key].Bool()
				}
			}
			if got != (val == "true") {
				t.Errorf("--%s=%s resulted in %v", name, val, got)
			}
		}
	}
}

func TestScalarFlagsOverrideYAML(t *testing.T) {
	doc := base + "outputs:\n  tcp:\n    address: yaml.example:9000\n  webhook:\n    url: https://yaml.example/hook\n    token_env: YAML_TOKEN\n"
	env := newFakeEnv().cwdFile(doc)
	env.vars["YAML_TOKEN"] = "x"

	r := mustResolve(t, env, "--tcp-address=", "--webhook-url=", "--webhook-token-env=")
	o := r.Config.Outputs
	if o.TCP.Address != "" || o.Webhook.URL != "" || o.Webhook.TokenEnv != "" {
		t.Errorf("explicit empty values did not clear YAML strings: %+v", o)
	}
	// A repeated scalar flag takes its last value.
	r = mustResolve(t, env, "--log-keep-files", "2", "--log-keep-files", "9")
	if r.Config.Outputs.File.KeepFiles != 9 {
		t.Errorf("keep_files = %d, want the last occurrence", r.Config.Outputs.File.KeepFiles)
	}
	// A required value cannot be blanked.
	errs := resolveErrors(t, env, "--log-file=")
	wantOneError(t, errs, "outputs.file.path", "must not be empty")
	errs = resolveErrors(t, env, "--exclude-scope=")
	wantOneError(t, errs, "exclude.scope")
}

func TestTCPOptionsMayBeClearedByFlags(t *testing.T) {
	doc := base + "outputs:\n  tcp:\n    tls: true\n    ca_file: /yaml/ca.pem\n    server_name: yaml.example\n"
	env := newFakeEnv().cwdFile(doc)
	r := mustResolve(t, env)
	if !r.Config.Outputs.TCP.TLS {
		t.Fatal("tls from YAML lost")
	}
	// Turning TLS off while the CA file is still configured is invalid ...
	errs := resolveErrors(t, env, "--tcp-tls=false")
	if got := paths(errs); !reflect.DeepEqual(got, []string{"outputs.tcp.ca_file", "outputs.tcp.server_name"}) {
		t.Errorf("paths = %q", got)
	}
	// ... unless those are cleared as well.
	r = mustResolve(t, env, "--tcp-tls=false", "--tcp-ca-file=", "--tcp-server-name=")
	if r.Config.Outputs.TCP.TLS || r.Config.Outputs.TCP.CAFile != "" || r.Config.Outputs.TCP.ServerName != "" {
		t.Errorf("tcp = %+v", r.Config.Outputs.TCP)
	}
}

func TestDoctorNeedsNoWatchPattern(t *testing.T) {
	r := mustResolve(t, newFakeEnv(), "doctor")
	if len(r.Config.Watch.ImageContains) != 0 {
		t.Errorf("doctor config has a watch list: %v", r.Config.Watch.ImageContains)
	}
	for _, cmd := range []string{"run", "check-config", "print-config"} {
		errs := resolveErrors(t, newFakeEnv(), cmd)
		wantOneError(t, errs, "watch.image_contains", "at least one pattern")
	}
	// Everything else is still validated for doctor.
	errs := resolveErrors(t, newFakeEnv(), "doctor", "--kill-enabled=true")
	wantOneError(t, errs, "kill.enabled")
	errs = resolveErrors(t, newFakeEnv(), "doctor", "--ring-buffer-mb", "3")
	wantOneError(t, errs, "runtime.ring_buffer_mb")
	// A YAML file without a watch list is fine for doctor.
	r = mustResolve(t, newFakeEnv().cwdFile("config_version: 1\n"), "doctor")
	if r.SourceFile != cfgPath {
		t.Errorf("SourceFile = %q", r.SourceFile)
	}
}

func TestResolveWithoutFullEnv(t *testing.T) {
	// A zero Env has no working directory.
	_, err := Resolve(withWatch(), Env{})
	wantOneError(t, flatten(err), "", "working directory")

	// Getwd alone is enough: no files, no environment, no executable.
	env := Env{Getwd: func() (string, error) { return "/work", nil }}
	r, err := Resolve(withWatch(), env)
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceFile != "" || r.Cwd != "/work" {
		t.Errorf("result = %+v", r)
	}
	// A missing environment makes an expected token missing.
	_, err = Resolve(withWatch("--webhook-url", "https://x.example/h", "--webhook-token-env", "T"), env)
	wantOneError(t, flatten(err), "outputs.webhook.token_env", "not set or empty")
	// An explicit file cannot be read without a file system.
	_, err = Resolve(withWatch("--config", "/x.yaml"), env)
	wantOneError(t, flatten(err), "--config", "does not exist")

	// Getwd failures and relative results are errors.
	_, err = Resolve(withWatch(), Env{Getwd: func() (string, error) { return "", errors.New("gone") }})
	wantOneError(t, flatten(err), "", "gone")
	_, err = Resolve(withWatch(), Env{Getwd: func() (string, error) { return "relative/dir", nil }})
	wantOneError(t, flatten(err), "", "not an absolute path")
}

func TestPartialEnvFallbacks(t *testing.T) {
	regular := func(string) (fs.FileInfo, error) { return fakeInfo{name: "x", mode: 0o644}, nil }
	// Stat without ReadFile: the file cannot be opened.
	env := Env{Getwd: func() (string, error) { return "/work", nil }, Stat: regular}
	_, err := Resolve(withWatch("--config", "/x.yaml"), env)
	wantOneError(t, flatten(err), "--config", "does not exist")

	// An Executable without EvalSymlinks is used as it is.
	files := map[string]string{"/opt/pw/process-watcher.yaml": base}
	env = Env{
		Getwd:      func() (string, error) { return "/work", nil },
		Executable: func() (string, error) { return "/opt/pw/process-watcher", nil },
		Stat: func(name string) (fs.FileInfo, error) {
			if _, ok := files[name]; !ok {
				return nil, fs.ErrNotExist
			}
			return regular(name)
		},
		ReadFile: func(name string) ([]byte, error) { return []byte(files[name]), nil },
	}
	r, err := Resolve(nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceFile != "/opt/pw/process-watcher.yaml" {
		t.Errorf("SourceFile = %q", r.SourceFile)
	}
}

// ---------------------------------------------------------------------------
// Configuration file search

func TestNoFileUsesDefaults(t *testing.T) {
	env := newFakeEnv()
	r := mustResolve(t, env, withWatch()...)
	if r.SourceFile != "" {
		t.Errorf("SourceFile = %q, want none", r.SourceFile)
	}
	for _, p := range []string{"/work/process-watcher.yaml", "/opt/pw/process-watcher.yaml"} {
		if env.stats[p] != 1 {
			t.Errorf("candidate %s was checked %d times, want once", p, env.stats[p])
		}
	}
	if len(env.reads) != 0 {
		t.Errorf("files were read: %v", env.reads)
	}
}

func TestFileSearchOrder(t *testing.T) {
	cwdDoc := base + "  max_depth: 1\n"
	binDoc := base + "  max_depth: 2\n"
	explicitDoc := base + "  max_depth: 3\n"

	t.Run("working directory", func(t *testing.T) {
		env := newFakeEnv().cwdFile(cwdDoc).file("/opt/pw/process-watcher.yaml", binDoc)
		r := mustResolve(t, env)
		if r.SourceFile != "/work/process-watcher.yaml" || r.Config.Watch.MaxDepth != 1 {
			t.Errorf("source %q depth %d, want the working directory file", r.SourceFile, r.Config.Watch.MaxDepth)
		}
		if env.stats["/opt/pw/process-watcher.yaml"] != 0 || env.reads["/opt/pw/process-watcher.yaml"] != 0 {
			t.Errorf("the binary directory was consulted although the working directory file exists")
		}
	})
	t.Run("next to the binary", func(t *testing.T) {
		env := newFakeEnv().file("/opt/pw/process-watcher.yaml", binDoc)
		r := mustResolve(t, env)
		if r.SourceFile != "/opt/pw/process-watcher.yaml" || r.Config.Watch.MaxDepth != 2 {
			t.Errorf("source %q depth %d, want the file next to the binary", r.SourceFile, r.Config.Watch.MaxDepth)
		}
	})
	t.Run("explicit file wins and others are not read", func(t *testing.T) {
		env := newFakeEnv().cwdFile(cwdDoc).file("/opt/pw/process-watcher.yaml", binDoc).file("/etc/pw.yaml", explicitDoc)
		r := mustResolve(t, env, "--config", "/etc/pw.yaml")
		if r.SourceFile != "/etc/pw.yaml" || r.Config.Watch.MaxDepth != 3 {
			t.Errorf("source %q depth %d, want the explicit file", r.SourceFile, r.Config.Watch.MaxDepth)
		}
		if env.stats["/work/process-watcher.yaml"] != 0 || env.reads["/work/process-watcher.yaml"] != 0 {
			t.Errorf("implicit candidates were consulted despite --config")
		}
	})
	t.Run("explicit relative path is resolved against the working directory", func(t *testing.T) {
		env := newFakeEnv().file("/work/conf/my.yaml", explicitDoc)
		r := mustResolve(t, env, "--config", "conf/../conf/my.yaml")
		if r.SourceFile != "/work/conf/my.yaml" {
			t.Errorf("SourceFile = %q", r.SourceFile)
		}
	})
	t.Run("explicit file may have any name", func(t *testing.T) {
		env := newFakeEnv().file("/etc/other.yml", explicitDoc)
		r := mustResolve(t, env, "-config=/etc/other.yml")
		if r.SourceFile != "/etc/other.yml" {
			t.Errorf("SourceFile = %q", r.SourceFile)
		}
	})
	t.Run("last --config wins", func(t *testing.T) {
		env := newFakeEnv().file("/a.yaml", base).file("/b.yaml", explicitDoc)
		r := mustResolve(t, env, "--config", "/a.yaml", "--config", "/b.yaml")
		if r.SourceFile != "/b.yaml" {
			t.Errorf("SourceFile = %q", r.SourceFile)
		}
	})
}

func TestExplicitConfigErrors(t *testing.T) {
	t.Run("missing file is an error and there is no fallback", func(t *testing.T) {
		env := newFakeEnv().cwdFile(base).file("/opt/pw/process-watcher.yaml", base)
		errs := resolveErrors(t, env, "--config", "/etc/missing.yaml")
		wantOneError(t, errs, "--config", "/etc/missing.yaml", "no such file or directory")
		if env.reads["/work/process-watcher.yaml"] != 0 {
			t.Error("fell back to the working directory file")
		}
	})
	t.Run("missing relative file", func(t *testing.T) {
		errs := resolveErrors(t, newFakeEnv(), "--config", "nope.yaml")
		wantOneError(t, errs, "--config", "/work/nope.yaml")
	})
	t.Run("empty path", func(t *testing.T) {
		errs := resolveErrors(t, newFakeEnv().cwdFile(base), "--config=")
		wantOneError(t, errs, "--config", "must not be empty")
	})
	t.Run("unreadable file", func(t *testing.T) {
		env := newFakeEnv().file("/etc/pw.yaml", base)
		env.readErr["/etc/pw.yaml"] = &fs.PathError{Op: "open", Path: "/etc/pw.yaml", Err: syscall.EACCES}
		errs := resolveErrors(t, env, "--config", "/etc/pw.yaml")
		wantOneError(t, errs, "--config", "permission denied")
	})
	t.Run("directory", func(t *testing.T) {
		env := newFakeEnv()
		env.dirs["/etc/pw.yaml"] = true
		errs := resolveErrors(t, env, "--config", "/etc/pw.yaml")
		wantOneError(t, errs, "--config", "not a regular file")
	})
	t.Run("too large", func(t *testing.T) {
		env := newFakeEnv().file("/etc/pw.yaml", base+"# "+strings.Repeat("x", maxFileBytes))
		errs := resolveErrors(t, env, "--config", "/etc/pw.yaml")
		wantOneError(t, errs, "--config", "larger than")
	})
	t.Run("invalid explicit file", func(t *testing.T) {
		env := newFakeEnv().file("/etc/pw.yaml", "watch: [")
		errs := resolveErrors(t, env, "--config", "/etc/pw.yaml")
		wantOneError(t, errs, "", "invalid YAML", "/etc/pw.yaml")
	})
}

func TestImplicitFileProblemsAreNeverSkipped(t *testing.T) {
	t.Run("invalid file in the working directory hides a valid one next to the binary", func(t *testing.T) {
		env := newFakeEnv().cwdFile("watch: [").file("/opt/pw/process-watcher.yaml", base)
		errs := resolveErrors(t, env)
		wantOneError(t, errs, "", "invalid YAML", "/work/process-watcher.yaml")
		if env.reads["/opt/pw/process-watcher.yaml"] != 0 {
			t.Error("the next candidate was read after an invalid one")
		}
	})
	t.Run("invalid file next to the binary", func(t *testing.T) {
		env := newFakeEnv().file("/opt/pw/process-watcher.yaml", "config_version: 1\nbogus: 1\n")
		errs := resolveErrors(t, env, withWatch()...)
		wantOneError(t, errs, "bogus", "/opt/pw/process-watcher.yaml:2")
	})
	t.Run("unreadable file", func(t *testing.T) {
		env := newFakeEnv().cwdFile(base).file("/opt/pw/process-watcher.yaml", base)
		env.readErr["/work/process-watcher.yaml"] = &fs.PathError{Op: "open", Path: "/work/process-watcher.yaml", Err: syscall.EACCES}
		errs := resolveErrors(t, env)
		wantOneError(t, errs, "", "cannot read configuration file", "permission denied", "/work/process-watcher.yaml")
		if env.reads["/opt/pw/process-watcher.yaml"] != 0 {
			t.Error("the next candidate was read after an unreadable one")
		}
	})
	t.Run("stat failure other than not-exist", func(t *testing.T) {
		env := newFakeEnv().file("/opt/pw/process-watcher.yaml", base)
		env.statErr["/work/process-watcher.yaml"] = &fs.PathError{Op: "stat", Path: "/work/process-watcher.yaml", Err: syscall.EACCES}
		errs := resolveErrors(t, env)
		wantOneError(t, errs, "", "permission denied")
	})
	t.Run("directory with the file name", func(t *testing.T) {
		env := newFakeEnv().file("/opt/pw/process-watcher.yaml", base)
		env.dirs["/work/process-watcher.yaml"] = true
		errs := resolveErrors(t, env)
		wantOneError(t, errs, "", "not a regular file")
	})
	t.Run("file vanishing between stat and read counts as missing", func(t *testing.T) {
		env := newFakeEnv().cwdFile(base)
		env.readErr["/work/process-watcher.yaml"] = &fs.PathError{Op: "open", Path: "/work/process-watcher.yaml", Err: syscall.ENOENT}
		r := mustResolve(t, env, withWatch()...)
		if r.SourceFile != "" {
			t.Errorf("SourceFile = %q", r.SourceFile)
		}
	})
}

func TestDuplicateCandidateIsLoadedOnce(t *testing.T) {
	// The binary lives in the working directory: both candidates are the same file.
	t.Run("present", func(t *testing.T) {
		env := newFakeEnv().cwdFile(base)
		env.exe = "/work/process-watcher"
		r := mustResolve(t, env)
		if r.SourceFile != "/work/process-watcher.yaml" {
			t.Fatalf("SourceFile = %q", r.SourceFile)
		}
		if env.stats["/work/process-watcher.yaml"] != 1 || env.reads["/work/process-watcher.yaml"] != 1 {
			t.Errorf("file was checked %d and read %d times, want once each", env.stats["/work/process-watcher.yaml"], env.reads["/work/process-watcher.yaml"])
		}
	})
	t.Run("absent", func(t *testing.T) {
		env := newFakeEnv()
		env.exe = "/work/process-watcher"
		mustResolve(t, env, withWatch()...)
		if n := env.stats["/work/process-watcher.yaml"]; n != 1 {
			t.Errorf("missing file was checked %d times, want once", n)
		}
	})
	t.Run("through a link and an unclean path", func(t *testing.T) {
		env := newFakeEnv()
		env.exe = "/usr/bin/../local/pw"
		env.links["/usr/local/pw"] = "/work//./process-watcher"
		mustResolve(t, env, withWatch()...)
		if n := env.stats["/work/process-watcher.yaml"]; n != 1 {
			t.Errorf("missing file was checked %d times, want once", n)
		}
	})
}

func TestBinaryDirectoryResolution(t *testing.T) {
	doc := base + "  max_depth: 5\n"
	t.Run("symlinked binary from another working directory", func(t *testing.T) {
		env := newFakeEnv()
		env.cwd = "/elsewhere"
		env.exe = "/usr/local/bin/pw"
		env.links["/usr/local/bin/pw"] = "/opt/real/process-watcher"
		env.file("/opt/real/process-watcher.yaml", doc)
		// A file next to the link must not be used.
		env.file("/usr/local/bin/process-watcher.yaml", base+"  max_depth: 9\n")
		r := mustResolve(t, env)
		if r.SourceFile != "/opt/real/process-watcher.yaml" || r.Config.Watch.MaxDepth != 5 {
			t.Errorf("source %q depth %d, want the file next to the real binary", r.SourceFile, r.Config.Watch.MaxDepth)
		}
		if r.Cwd != "/elsewhere" {
			t.Errorf("Cwd = %q", r.Cwd)
		}
	})
	t.Run("relative executable path", func(t *testing.T) {
		env := newFakeEnv()
		env.exe = "bin/process-watcher"
		env.file("/work/bin/process-watcher.yaml", doc)
		r := mustResolve(t, env)
		if r.SourceFile != "/work/bin/process-watcher.yaml" {
			t.Errorf("SourceFile = %q", r.SourceFile)
		}
	})
	t.Run("unknown binary location disables the search", func(t *testing.T) {
		for name, mutate := range map[string]func(*fakeEnv){
			"error": func(e *fakeEnv) { e.exeErr = errors.New("no /proc") },
			"empty": func(e *fakeEnv) { e.exe = "" },
		} {
			env := newFakeEnv().file("/opt/pw/process-watcher.yaml", doc)
			mutate(env)
			r := mustResolve(t, env, withWatch()...)
			if r.SourceFile != "" {
				t.Errorf("%s: SourceFile = %q", name, r.SourceFile)
			}
		}
	})
	t.Run("unresolvable link disables the search", func(t *testing.T) {
		env := newFakeEnv().file("/opt/pw/process-watcher.yaml", doc)
		e := env.Env()
		e.EvalSymlinks = func(string) (string, error) { return "", errors.New("deleted") }
		r, err := Resolve(withWatch(), e)
		if err != nil || r.SourceFile != "" {
			t.Errorf("result %+v, error %v", r, err)
		}
	})
}

// The same search with real files and a real symlink.
func TestRealSymlinkedBinaryFromAnotherDirectory(t *testing.T) {
	realDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	linkDir := t.TempDir()
	elsewhere := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(realDir, "process-watcher"), "#!/bin/sh\n")
	write(filepath.Join(realDir, DefaultFileName), base+"  max_depth: 6\n")
	write(filepath.Join(linkDir, DefaultFileName), base+"  max_depth: 7\n") // next to the link: must be ignored
	link := filepath.Join(linkDir, "process-watcher")
	if err := os.Symlink(filepath.Join(realDir, "process-watcher"), link); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}

	env := OSEnv()
	env.Getwd = func() (string, error) { return elsewhere, nil }
	env.Executable = func() (string, error) { return link, nil }
	r, err := Resolve(nil, env)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(realDir, DefaultFileName)
	if r.SourceFile != want {
		t.Errorf("SourceFile = %q, want %q", r.SourceFile, want)
	}
	if r.Config.Watch.MaxDepth != 6 {
		t.Errorf("max_depth = %d, want the value of the file next to the real binary", r.Config.Watch.MaxDepth)
	}

	// A file in the working directory takes precedence.
	write(filepath.Join(elsewhere, DefaultFileName), base+"  max_depth: 8\n")
	r, err = Resolve(nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if r.Config.Watch.MaxDepth != 8 || r.SourceFile != filepath.Join(elsewhere, DefaultFileName) {
		t.Errorf("source %q depth %d, want the working directory file", r.SourceFile, r.Config.Watch.MaxDepth)
	}
}

func TestOSEnvReadsRealFiles(t *testing.T) {
	dir := t.TempDir()
	env := OSEnv()
	env.Getwd = func() (string, error) { return dir, nil }
	env.Executable = func() (string, error) { return "", errors.New("unused") }

	file := filepath.Join(dir, "conf.yaml")
	if err := os.WriteFile(file, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve([]string{"--config", "conf.yaml"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(file); r.SourceFile != file && r.SourceFile != want {
		t.Errorf("SourceFile = %q", r.SourceFile)
	}

	// Missing explicit file.
	_, err = Resolve([]string{"--config", filepath.Join(dir, "nope.yaml")}, env)
	wantOneError(t, flatten(err), "--config", "no such file or directory")

	// Directory instead of a file.
	_, err = Resolve([]string{"--config", dir}, env)
	wantOneError(t, flatten(err), "--config", "not a regular file")

	// An oversized file is refused by the real reader.
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, []byte(base+"# "+strings.Repeat("x", maxFileBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Resolve([]string{"--config", big}, env)
	wantOneError(t, flatten(err), "--config", "larger than")

	if OSEnv().Getenv == nil || OSEnv().Getwd == nil || OSEnv().Executable == nil || OSEnv().ReadFile == nil ||
		OSEnv().Stat == nil || OSEnv().EvalSymlinks == nil {
		t.Error("OSEnv leaves a function unset")
	}
}

// ---------------------------------------------------------------------------
// Relative paths

func TestRelativePathsResolveAgainstTheWorkingDirectory(t *testing.T) {
	doc := base + "outputs:\n  file:\n    path: logs/events.jsonl\n  tcp:\n    tls: true\n    ca_file: certs/../certs/ca.pem\n"
	t.Run("from YAML, config elsewhere", func(t *testing.T) {
		env := newFakeEnv().file("/etc/pw/config.yaml", doc)
		env.cwd = "/srv/run"
		r := mustResolve(t, env, "--config", "/etc/pw/config.yaml")
		if got := r.Config.Outputs.File.Path; got != "/srv/run/logs/events.jsonl" {
			t.Errorf("log path = %q, want it relative to the working directory, not to the file", got)
		}
		if got := r.Config.Outputs.TCP.CAFile; got != "/srv/run/certs/ca.pem" {
			t.Errorf("ca_file = %q", got)
		}
		if r.Cwd != "/srv/run" {
			t.Errorf("Cwd = %q", r.Cwd)
		}
	})
	t.Run("from flags", func(t *testing.T) {
		env := newFakeEnv()
		env.cwd = "/srv/run"
		r := mustResolve(t, env, withWatch("--log-file", "../logs//events.jsonl", "--tcp-tls", "--tcp-ca-file", "./ca.pem")...)
		if got := r.Config.Outputs.File.Path; got != "/srv/logs/events.jsonl" {
			t.Errorf("log path = %q", got)
		}
		if got := r.Config.Outputs.TCP.CAFile; got != "/srv/run/ca.pem" {
			t.Errorf("ca_file = %q", got)
		}
	})
	t.Run("absolute paths are cleaned", func(t *testing.T) {
		r := mustResolve(t, newFakeEnv(), withWatch("--log-file", "/var//log/../log/pw/events.jsonl", "--tcp-tls", "--tcp-ca-file", "/etc/ssl//ca.pem")...)
		if got := r.Config.Outputs.File.Path; got != "/var/log/pw/events.jsonl" {
			t.Errorf("log path = %q", got)
		}
		if got := r.Config.Outputs.TCP.CAFile; got != "/etc/ssl/ca.pem" {
			t.Errorf("ca_file = %q", got)
		}
	})
	t.Run("default log path", func(t *testing.T) {
		env := newFakeEnv()
		env.cwd = "/srv/run/"
		r := mustResolve(t, env, withWatch()...)
		if got := r.Config.Outputs.File.Path; got != "/srv/run/process-watcher.jsonl" {
			t.Errorf("log path = %q", got)
		}
		if r.Cwd != "/srv/run" {
			t.Errorf("Cwd = %q, want the cleaned directory", r.Cwd)
		}
	})
	t.Run("empty ca_file stays empty", func(t *testing.T) {
		r := mustResolve(t, newFakeEnv(), withWatch()...)
		if r.Config.Outputs.TCP.CAFile != "" {
			t.Errorf("ca_file = %q", r.Config.Outputs.TCP.CAFile)
		}
	})
	t.Run("relative paths are not resolved into other values", func(t *testing.T) {
		r := mustResolve(t, newFakeEnv(), withWatch("--exclude-image-contains", "./relative", "--kill-string", "../x", "--tcp-server-name=", "--webhook-url", "https://x.example/a/../b")...)
		if r.Config.Exclude.ImageContains[0] != "./relative" || r.Config.Kill.Strings[0] != "../x" || r.Config.Outputs.Webhook.URL != "https://x.example/a/../b" {
			t.Errorf("non-path values were rewritten: %+v", r.Config)
		}
	})
}

// ---------------------------------------------------------------------------
// Webhook token

func TestResolveWebhookToken(t *testing.T) {
	cfg := Default()
	cfg.Outputs.Webhook.URL = "https://collector.example.net/hook"
	cfg.Outputs.Webhook.TokenEnv = "PW_TOKEN"
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	tests := []struct {
		name    string
		mutate  func(c *Config)
		getenv  func(string) string
		want    string
		wantErr string
	}{
		{"set", nil, get(map[string]string{"PW_TOKEN": "abc"}), "abc", ""},
		{"surrounding spaces are kept", nil, get(map[string]string{"PW_TOKEN": " abc "}), " abc ", ""},
		{"missing", nil, get(nil), "", "environment variable PW_TOKEN is not set or empty"},
		{"empty", nil, get(map[string]string{"PW_TOKEN": ""}), "", "not set or empty"},
		{"nil getenv", nil, nil, "", "not set or empty"},
		{"other variable only", nil, get(map[string]string{"OTHER": "abc"}), "", "not set or empty"},
		{"trailing newline", nil, get(map[string]string{"PW_TOKEN": "SECRETVALUE\n"}), "", "control characters"},
		{"carriage return", nil, get(map[string]string{"PW_TOKEN": "SECRET\rVALUE"}), "", "control characters"},
		{"nul", nil, get(map[string]string{"PW_TOKEN": "SECRET\x00VALUE"}), "", "control characters"},
		{"del", nil, get(map[string]string{"PW_TOKEN": "SECRET\x7fVALUE"}), "", "control characters"},
		{"no token_env", func(c *Config) { c.Outputs.Webhook.TokenEnv = "" }, get(nil), "", ""},
		{"no url", func(c *Config) { c.Outputs.Webhook.URL = "" }, get(nil), "", ""},
		{"no url but token set", func(c *Config) { c.Outputs.Webhook.URL = "" }, get(map[string]string{"PW_TOKEN": "abc"}), "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			got, err := ResolveWebhookToken(c, tc.getenv)
			if tc.wantErr == "" {
				if err != nil || got != tc.want {
					t.Errorf("ResolveWebhookToken = %q, %v; want %q, nil", got, err, tc.want)
				}
				return
			}
			var ce *Error
			if !errors.As(err, &ce) || ce.Path != "outputs.webhook.token_env" {
				t.Fatalf("error = %#v, want *Error for outputs.webhook.token_env", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
			if got != "" {
				t.Errorf("token %q returned together with an error", got)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "VALUE") {
				t.Errorf("error leaks the token: %q", err)
			}
		})
	}
}

func TestWebhookTokenCheckDependsOnTheCommand(t *testing.T) {
	args := []string{"--watch-image-contains", "nginx", "--webhook-url", "https://collector.example.net/hook", "--webhook-token-env", "PW_TOKEN"}
	for _, cmd := range []string{"run", "check-config"} {
		env := newFakeEnv()
		errs := resolveErrors(t, env, append([]string{cmd}, args...)...)
		wantOneError(t, errs, "outputs.webhook.token_env", "PW_TOKEN", "set by flag --webhook-token-env")
		if !reflect.DeepEqual(env.envKeys, []string{"PW_TOKEN"}) {
			t.Errorf("%s read the variables %v, want only PW_TOKEN", cmd, env.envKeys)
		}
		env.vars["PW_TOKEN"] = "SECRETVALUE"
		r := mustResolve(t, env, append([]string{cmd}, args...)...)
		if r.Config.Outputs.Webhook.TokenEnv != "PW_TOKEN" {
			t.Errorf("token_env = %q", r.Config.Outputs.Webhook.TokenEnv)
		}
		if strings.Contains(strings.Join(flatStrings(r.Config), "|"), "SECRETVALUE") {
			t.Errorf("the token value was stored in the configuration")
		}
	}
	for _, cmd := range []string{"print-config", "doctor"} {
		env := newFakeEnv()
		mustResolve(t, env, append([]string{cmd}, args...)...)
		if len(env.envKeys) != 0 {
			t.Errorf("%s read environment variables %v", cmd, env.envKeys)
		}
	}
}

func TestWebhookTokenErrorCarriesYAMLLine(t *testing.T) {
	doc := base + "outputs:\n  webhook:\n    url: https://collector.example.net/hook\n    token_env: PW_TOKEN\n"
	errs := resolveErrors(t, newFakeEnv().cwdFile(doc))
	e := wantOneError(t, errs, "outputs.webhook.token_env", "PW_TOKEN")
	if e.File != cfgPath || e.Line != 7 {
		t.Errorf("origin = {%q, %d}, want {%q, 7}", e.File, e.Line, cfgPath)
	}
}

// flatStrings returns every string of a configuration.
func flatStrings(c Config) []string {
	var out []string
	for _, l := range leaves(&c) {
		switch l.Val.Kind() {
		case reflect.String:
			out = append(out, l.Val.String())
		case reflect.Slice:
			for i := range l.Val.Len() {
				out = append(out, l.Val.Index(i).String())
			}
		}
	}
	return out
}

func TestCheckFilesRejectsAnUnusableCAFile(t *testing.T) {
	const validPEM = `-----BEGIN CERTIFICATE-----
MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
YyRIHN8wfdVoOw==
-----END CERTIFICATE-----
`
	base := []string{"--watch-image-contains", "nginx", "--tcp-address", "collector.example.net:9000", "--tcp-tls"}
	withCA := func(path string) []string { return append(append([]string{}, base...), "--tcp-ca-file", path) }
	for _, tc := range []struct {
		name    string
		files   map[string]string
		readErr error
		args    []string
		want    string // substring of the error, "" for no error
	}{
		{"no ca file", nil, nil, base, ""},
		{"valid bundle", map[string]string{"/work/ca.pem": validPEM}, nil, withCA("ca.pem"), ""},
		{"missing file", nil, nil, withCA("/nonexistent/ca.pem"), "outputs.tcp.ca_file: cannot read the CA file"},
		{"no certificate", map[string]string{"/work/ca.pem": "not a certificate\n"}, nil, withCA("ca.pem"), "contains no valid PEM certificate"},
		{"unreadable", map[string]string{"/work/ca.pem": validPEM}, syscall.EACCES, withCA("ca.pem"), "permission denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newFakeEnv()
			for p, c := range tc.files {
				env.files[p] = c
			}
			if tc.readErr != nil {
				env.readErr["/work/ca.pem"] = tc.readErr
			}
			// Resolve itself never reads the CA file: it must succeed in every case.
			r := mustResolve(t, env, append([]string{"check-config"}, tc.args...)...)
			err := CheckFiles(r.Config, env.Env())
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("CheckFiles: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("CheckFiles = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
