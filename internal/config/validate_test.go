package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultsAreValid(t *testing.T) {
	cfg := Default()
	if errs := validate(&cfg, false); len(errs) != 0 {
		t.Errorf("defaults are invalid without a watch list: %v", errs)
	}
	errs := validate(&cfg, true)
	wantOneError(t, errs, "watch.image_contains", "at least one pattern")

	cfg.Watch.ImageContains = []string{"nginx"}
	if errs := validate(&cfg, true); len(errs) != 0 {
		t.Errorf("defaults plus a watch pattern are invalid: %v", errs)
	}
}

// validationCases drive every rule through the whole of Resolve with flags.
// An empty paths list means the arguments must be accepted.
var validationCases = []struct {
	name    string
	args    []string // after --watch-image-contains nginx unless noWatch
	noWatch bool
	paths   []string
	msg     string // fragment of the first error
}{
	// watch
	{name: "watch list missing", noWatch: true, paths: []string{"watch.image_contains"}, msg: "at least one pattern"},
	{name: "watch list cleared", noWatch: true, args: []string{"--watch-image-contains="}, paths: []string{"watch.image_contains"}, msg: "at least one pattern"},
	{name: "watch list cleared after values", noWatch: true, args: []string{"--watch-image-contains", "a", "--watch-image-contains="}, paths: []string{"--watch-image-contains"}, msg: "single empty value clears"},
	{name: "max depth negative", args: []string{"--watch-max-depth", "-1"}, paths: []string{"watch.max_depth"}, msg: "0 (unlimited)"},
	{name: "max depth zero is fine", args: []string{"--watch-max-depth", "0"}},
	{name: "max depth positive", args: []string{"--watch-max-depth=7"}},

	// exclude
	{name: "scope bogus", args: []string{"--exclude-scope", "everything"}, paths: []string{"exclude.scope"}, msg: `"remote" or "all"`},
	{name: "scope empty", args: []string{"--exclude-scope="}, paths: []string{"exclude.scope"}},
	{name: "scope all", args: []string{"--exclude-scope", "all"}},
	{name: "scope is case sensitive", args: []string{"--exclude-scope", "ALL"}, paths: []string{"exclude.scope"}},
	{name: "exclude argv needs capture", args: []string{"--exclude-argv-contains", "x"}, paths: []string{"exclude.argv_contains"}, msg: "capture.argv: true"},
	{name: "exclude argv with capture", args: []string{"--exclude-argv-contains", "x", "--capture-argv"}},
	{name: "exclude image needs no capture", args: []string{"--exclude-image-contains", "x"}},

	// capture limits
	{name: "argv limits need capture", args: []string{"--capture-argv-max-bytes", "8000"}, paths: []string{"capture.argv_max_bytes"}, msg: "capture.argv: true"},
	{name: "argv count limit needs capture", args: []string{"--capture-argv-max-args", "64"}, paths: []string{"capture.argv_max_args"}, msg: "capture.argv: true"},
	{name: "argv defaults need no capture", args: []string{"--capture-argv-max-bytes", "4096", "--capture-argv-max-args", "32"}},
	{name: "argv limits with capture", args: []string{"--capture-argv", "--capture-argv-max-bytes", "16383", "--capture-argv-max-args", "1024"}},
	{name: "argv bytes above the kernel buffer", args: []string{"--capture-argv", "--capture-argv-max-bytes", "16384"}, paths: []string{"capture.argv_max_bytes"}, msg: "between 256 and 16383"},
	{name: "argv bytes below the minimum", args: []string{"--capture-argv", "--capture-argv-max-bytes", "255"}, paths: []string{"capture.argv_max_bytes"}, msg: "between 256 and 16383"},
	{name: "argv count zero", args: []string{"--capture-argv", "--capture-argv-max-args", "0"}, paths: []string{"capture.argv_max_args"}, msg: "between 1 and 1024"},
	{name: "argv count above the maximum", args: []string{"--capture-argv", "--capture-argv-max-args", "1025"}, paths: []string{"capture.argv_max_args"}},
	{name: "argv limits are integers", args: []string{"--capture-argv", "--capture-argv-max-bytes", "4k"}, paths: []string{"--capture-argv-max-bytes"}},

	// kill: shape errors
	{name: "kill unknown field", args: []string{"--kill-field", "bogus"}, paths: []string{"kill.fields[0]"}, msg: `unknown field "bogus"`},
	{name: "kill field is case sensitive", args: []string{"--kill-field", "image", "--kill-field", "Image"}, paths: []string{"kill.fields[1]"}},
	{name: "kill field list empty", args: []string{"--kill-field="}, paths: []string{"kill.fields"}, msg: "at least one field"},
	{name: "kill field list empty even if disabled", args: []string{"--kill-enabled=false", "--kill-field="}, paths: []string{"kill.fields"}},
	{name: "kill bad regex", args: []string{"--kill-regex", "("}, paths: []string{"kill.regex[0]"}, msg: "missing closing ): `(`"},
	{name: "kill bad regex index", args: []string{"--kill-regex", "a", "--kill-regex", "b", "--kill-regex", "[x"}, paths: []string{"kill.regex[2]"}, msg: "error parsing regexp"},
	{name: "kill unsupported regex syntax", args: []string{"--kill-regex", `(?=x)`}, paths: []string{"kill.regex[0]"}, msg: "invalid or unsupported Perl syntax"},
	{name: "kill regex backreference", args: []string{"--kill-regex", `(a)\1`}, paths: []string{"kill.regex[0]"}, msg: "invalid escape sequence"},
	{name: "kill bad regex while disabled", args: []string{"--kill-enabled=false", "--kill-regex", "("}, paths: []string{"kill.regex[0]"}},
	{name: "kill two bad regexes", args: []string{"--kill-regex", "(", "--kill-regex", "ok", "--kill-regex", "*"}, paths: []string{"kill.regex[0]", "kill.regex[2]"}},
	{name: "kill good regexes", args: []string{"--kill-regex", `^(useradd|usermod)$`, "--kill-regex", `(?i)curl`}},
	{name: "kill string with commas", args: []string{"--kill-string", "a,b"}},

	// kill: cross checks only when enabled
	{name: "kill enabled without rules", args: []string{"--kill-enabled=true"}, paths: []string{"kill.enabled"}, msg: "at least one rule"},
	{name: "kill disabled without rules", args: []string{"--kill-enabled=false"}},
	{name: "kill enabled with string", args: []string{"--kill-enabled=true", "--kill-string", "x"}},
	{name: "kill enabled with regex", args: []string{"--kill-enabled=true", "--kill-regex", "^x$"}},
	{name: "kill argv without capture", args: []string{"--kill-enabled=true", "--kill-string", "x", "--kill-field", "argv"}, paths: []string{"kill.fields[0]"}, msg: "capture.argv: true"},
	{name: "kill argv index in list", args: []string{"--kill-enabled=true", "--kill-string", "x", "--kill-field", "image", "--kill-field", "argv"}, paths: []string{"kill.fields[1]"}},
	{name: "kill argv with capture", args: []string{"--kill-enabled=true", "--kill-string", "x", "--kill-field", "argv", "--capture-argv=true"}},
	{name: "kill argv while disabled", args: []string{"--kill-enabled=false", "--kill-string", "x", "--kill-field", "argv"}},
	{name: "kill duplicates allowed", args: []string{"--kill-enabled=true", "--kill-string", "x", "--kill-string", "x", "--kill-field", "image", "--kill-field", "image"}},
	{name: "kill duplicate argv flagged twice", args: []string{"--kill-enabled=true", "--kill-string", "x", "--kill-field", "argv", "--kill-field", "argv"}, paths: []string{"kill.fields[0]", "kill.fields[1]"}},
	{name: "kill without rules and argv", args: []string{"--kill-enabled=true", "--kill-field", "argv"}, paths: []string{"kill.enabled", "kill.fields[0]"}},
	{name: "kill dry run alone", args: []string{"--kill-dry-run"}},
	{name: "kill spare root image alone", args: []string{"--kill-spare-root-image"}},
	{name: "kill spare root image with rules", args: []string{"--kill-enabled=true", "--kill-string", "php", "--kill-spare-root-image=true"}},
	{name: "kill spec one-liner", args: []string{"--capture-argv=true", "--kill-enabled=true", "--kill-field", "image", "--kill-field", "argv", "--kill-string", "demo-long-running-helper", "--kill-regex", "^(useradd|usermod)$"}},

	// local log
	{name: "log path empty", args: []string{"--log-file="}, paths: []string{"outputs.file.path"}, msg: "must not be empty"},
	{name: "log path directory", args: []string{"--log-file", "/var/log/"}, paths: []string{"outputs.file.path"}, msg: "not a directory"},
	{name: "log path dot", args: []string{"--log-file", "."}, paths: []string{"outputs.file.path"}},
	{name: "log path dotdot", args: []string{"--log-file", "a/.."}, paths: []string{"outputs.file.path"}},
	{name: "log path relative", args: []string{"--log-file", "events.jsonl"}},
	{name: "rotate zero", args: []string{"--log-rotate-size-mb", "0"}, paths: []string{"outputs.file.rotate_size_mb"}, msg: "between 1 and"},
	{name: "rotate negative", args: []string{"--log-rotate-size-mb", "-5"}, paths: []string{"outputs.file.rotate_size_mb"}},
	{name: "rotate too large", args: []string{"--log-rotate-size-mb", "1048577"}, paths: []string{"outputs.file.rotate_size_mb"}},
	{name: "rotate at limit", args: []string{"--log-rotate-size-mb", "1048576"}},
	{name: "keep zero", args: []string{"--log-keep-files", "0"}, paths: []string{"outputs.file.keep_files"}},
	{name: "keep one", args: []string{"--log-keep-files", "1"}},
	{name: "keep too many", args: []string{"--log-keep-files", "10001"}, paths: []string{"outputs.file.keep_files"}},
	{name: "sync zero", args: []string{"--log-sync-interval", "0s"}, paths: []string{"outputs.file.sync_interval"}, msg: "positive duration"},
	{name: "sync negative", args: []string{"--log-sync-interval", "-1s"}, paths: []string{"outputs.file.sync_interval"}},
	{name: "sync subsecond", args: []string{"--log-sync-interval", "250ms"}},

	// tcp
	{name: "tcp ipv4", args: []string{"--tcp-address", "192.0.2.10:9000"}},
	{name: "tcp dns", args: []string{"--tcp-address", "collector.example.net:9000"}},
	{name: "tcp ipv6", args: []string{"--tcp-address", "[2001:db8::10]:9000"}},
	{name: "tcp missing port", args: []string{"--tcp-address", "collector.example.net"}, paths: []string{"outputs.tcp.address"}, msg: "missing port"},
	{name: "tcp unbracketed ipv6", args: []string{"--tcp-address", "2001:db8::10:9000"}, paths: []string{"outputs.tcp.address"}, msg: "enclosed in brackets"},
	{name: "tcp port zero", args: []string{"--tcp-address", "host.example:0"}, paths: []string{"outputs.tcp.address"}, msg: "between 1 and 65535"},
	{name: "tcp port too large", args: []string{"--tcp-address", "host.example:65536"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp port named", args: []string{"--tcp-address", "host.example:http"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp empty host", args: []string{"--tcp-address", ":9000"}, paths: []string{"outputs.tcp.address"}, msg: "host must not be empty"},
	{name: "tcp url scheme", args: []string{"--tcp-address", "tcp://host.example:9000"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp brackets around name", args: []string{"--tcp-address", "[host.example]:9000"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp brackets around ipv4", args: []string{"--tcp-address", "[192.0.2.1]:9000"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp bad ipv4", args: []string{"--tcp-address", "256.1.1.1:9000"}, paths: []string{"outputs.tcp.address"}, msg: "neither a valid IP address"},
	{name: "tcp short ipv4", args: []string{"--tcp-address", "192.0.2:9000"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp space in host", args: []string{"--tcp-address", "bad host:9000"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp leading hyphen", args: []string{"--tcp-address", "-bad.example:9000"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp empty label", args: []string{"--tcp-address", "a..b:9000"}, paths: []string{"outputs.tcp.address"}},
	{name: "tcp non ascii", args: []string{"--tcp-address", "пример.example:9000"}, paths: []string{"outputs.tcp.address"}, msg: "punycode"},
	{name: "tcp punycode", args: []string{"--tcp-address", "xn--mnchen-3ya.example:9000"}},
	{name: "tcp underscore and dot", args: []string{"--tcp-address", "my_host.internal.:65535"}},
	{name: "tcp localhost", args: []string{"--tcp-address", "localhost:1"}},
	{name: "tcp ipv6 zone", args: []string{"--tcp-address", "[fe80::1%eth0]:9000"}},
	{name: "tcp address cleared", args: []string{"--tcp-address="}},
	{name: "tcp ca needs tls", args: []string{"--tcp-ca-file", "ca.pem"}, paths: []string{"outputs.tcp.ca_file"}, msg: "outputs.tcp.tls: true"},
	{name: "tcp ca with tls", args: []string{"--tcp-ca-file", "ca.pem", "--tcp-tls"}},
	{name: "tcp server name needs tls", args: []string{"--tcp-server-name", "collector.example.net"}, paths: []string{"outputs.tcp.server_name"}, msg: "outputs.tcp.tls: true"},
	{name: "tcp server name with tls", args: []string{"--tcp-server-name", "collector.example.net", "--tcp-tls"}},
	{name: "tcp server name ip", args: []string{"--tcp-server-name", "192.0.2.1", "--tcp-tls"}},
	{name: "tcp server name invalid", args: []string{"--tcp-server-name", "bad name", "--tcp-tls"}, paths: []string{"outputs.tcp.server_name"}, msg: "invalid server name"},
	{name: "tcp server name with port", args: []string{"--tcp-server-name", "host:9000", "--tcp-tls"}, paths: []string{"outputs.tcp.server_name"}},
	{name: "tcp tls alone is fine", args: []string{"--tcp-tls"}},
	{name: "tcp both tls errors", args: []string{"--tcp-ca-file", "ca.pem", "--tcp-server-name", "x.example"}, paths: []string{"outputs.tcp.ca_file", "outputs.tcp.server_name"}},

	// udp
	{name: "udp ok", args: []string{"--udp-address", "192.0.2.20:9001"}},
	{name: "udp bad address", args: []string{"--udp-address", "192.0.2.20"}, paths: []string{"outputs.udp.address"}, msg: "missing port"},
	{name: "udp max below", args: []string{"--udp-max-bytes", "511"}, paths: []string{"outputs.udp.max_bytes"}, msg: "between 512 and 65507"},
	{name: "udp max lower bound", args: []string{"--udp-max-bytes", "512"}},
	{name: "udp max upper bound", args: []string{"--udp-max-bytes", "65507"}},
	{name: "udp max above", args: []string{"--udp-max-bytes", "65508"}, paths: []string{"outputs.udp.max_bytes"}},

	// webhook
	{name: "webhook https", args: []string{"--webhook-url", "https://collector.example.net/hooks/processes"}},
	{name: "webhook http internal", args: []string{"--webhook-url", "http://10.0.0.5:8080/hook"}},
	{name: "webhook with query", args: []string{"--webhook-url", "https://collector.example.net/hooks?token=abc&x=1"}},
	{name: "webhook ipv6", args: []string{"--webhook-url", "https://[2001:db8::1]:8443/x"}},
	{name: "webhook uppercase scheme", args: []string{"--webhook-url", "HTTPS://collector.example.net/x"}},
	{name: "webhook ftp", args: []string{"--webhook-url", "ftp://collector.example.net/x"}, paths: []string{"outputs.webhook.url"}, msg: "http or https"},
	{name: "webhook no scheme", args: []string{"--webhook-url", "collector.example.net/hook"}, paths: []string{"outputs.webhook.url"}, msg: "http:// or https://"},
	{name: "webhook credentials", args: []string{"--webhook-url", "https://user:pw@collector.example.net/x"}, paths: []string{"outputs.webhook.url"}, msg: "credentials"},
	{name: "webhook user only", args: []string{"--webhook-url", "https://user@collector.example.net/x"}, paths: []string{"outputs.webhook.url"}},
	{name: "webhook fragment", args: []string{"--webhook-url", "https://collector.example.net/x#frag"}, paths: []string{"outputs.webhook.url"}, msg: "fragment"},
	{name: "webhook empty fragment", args: []string{"--webhook-url", "https://collector.example.net/x#"}, paths: []string{"outputs.webhook.url"}, msg: "fragment"},
	{name: "webhook no host", args: []string{"--webhook-url", "https:///path"}, paths: []string{"outputs.webhook.url"}, msg: "host"},
	{name: "webhook opaque", args: []string{"--webhook-url", "https:collector.example.net"}, paths: []string{"outputs.webhook.url"}},
	{name: "webhook javascript", args: []string{"--webhook-url", "javascript:alert(1)"}, paths: []string{"outputs.webhook.url"}},
	{name: "webhook bad port", args: []string{"--webhook-url", "https://collector.example.net:99999/x"}, paths: []string{"outputs.webhook.url"}, msg: "between 1 and 65535"},
	{name: "webhook empty port", args: []string{"--webhook-url", "https://collector.example.net:/x"}, paths: []string{"outputs.webhook.url"}, msg: "port"},
	{name: "webhook space", args: []string{"--webhook-url", "https://collector.example.net/a b"}, paths: []string{"outputs.webhook.url"}, msg: "whitespace"},
	{name: "webhook bad host", args: []string{"--webhook-url", "https://-bad.example/x"}, paths: []string{"outputs.webhook.url"}, msg: "invalid host"},
	{name: "webhook cleared", args: []string{"--webhook-url="}},
	{name: "token env ok", args: []string{"--webhook-token-env", "WEBHOOK_TOKEN_1"}},
	{name: "token env with dash", args: []string{"--webhook-token-env", "my-token"}, paths: []string{"outputs.webhook.token_env"}, msg: "not the token itself"},
	{name: "token env leading digit", args: []string{"--webhook-token-env", "1TOKEN"}, paths: []string{"outputs.webhook.token_env"}},
	{name: "token env with equals", args: []string{"--webhook-token-env", "A=b"}, paths: []string{"outputs.webhook.token_env"}},
	{name: "webhook timeout zero", args: []string{"--webhook-timeout", "0s"}, paths: []string{"outputs.webhook.timeout"}},
	{name: "webhook timeout negative", args: []string{"--webhook-timeout", "-5s"}, paths: []string{"outputs.webhook.timeout"}},

	// delivery
	{name: "queue zero", args: []string{"--queue-size", "0"}, paths: []string{"delivery.queue_size"}, msg: "between 1 and"},
	{name: "queue one", args: []string{"--queue-size", "1"}},
	{name: "queue huge", args: []string{"--queue-size", "1048577"}, paths: []string{"delivery.queue_size"}},
	{name: "connect timeout zero", args: []string{"--connect-timeout", "0s"}, paths: []string{"delivery.connect_timeout"}},
	{name: "write timeout negative", args: []string{"--write-timeout", "-1s"}, paths: []string{"delivery.write_timeout"}},
	{name: "retries negative", args: []string{"--max-retries", "-1"}, paths: []string{"delivery.max_retries"}, msg: "0 or greater"},
	{name: "retries zero", args: []string{"--max-retries", "0"}},

	// runtime
	{name: "ring zero", args: []string{"--ring-buffer-mb", "0"}, paths: []string{"runtime.ring_buffer_mb"}, msg: "power of two"},
	{name: "ring negative", args: []string{"--ring-buffer-mb", "-4"}, paths: []string{"runtime.ring_buffer_mb"}},
	{name: "ring three", args: []string{"--ring-buffer-mb", "3"}, paths: []string{"runtime.ring_buffer_mb"}},
	{name: "ring six", args: []string{"--ring-buffer-mb", "6"}, paths: []string{"runtime.ring_buffer_mb"}},
	{name: "ring one", args: []string{"--ring-buffer-mb", "1"}},
	{name: "ring 64", args: []string{"--ring-buffer-mb", "64"}},
	{name: "ring at upper bound", args: []string{"--ring-buffer-mb", "1024"}},
	{name: "ring above upper bound", args: []string{"--ring-buffer-mb", "2048"}, paths: []string{"runtime.ring_buffer_mb"}, msg: "1024"},
	{name: "max processes zero", args: []string{"--max-processes", "0"}, paths: []string{"runtime.max_processes"}},
	{name: "max processes huge", args: []string{"--max-processes", "16777217"}, paths: []string{"runtime.max_processes"}},
	{name: "health zero", args: []string{"--health-interval", "0s"}, paths: []string{"runtime.health_interval"}},
	{name: "reconcile negative", args: []string{"--reconcile-interval", "-30s"}, paths: []string{"runtime.reconcile_interval"}},
	{name: "shutdown zero", args: []string{"--shutdown-timeout", "0s"}, paths: []string{"runtime.shutdown_timeout"}},

	// several problems are reported together, in configuration order
	{name: "all errors at once", args: []string{"--watch-max-depth", "-1", "--exclude-scope", "x", "--log-keep-files", "0", "--ring-buffer-mb", "3"},
		paths: []string{"watch.max_depth", "exclude.scope", "outputs.file.keep_files", "runtime.ring_buffer_mb"}},
}

func TestValidationRules(t *testing.T) {
	for _, tc := range validationCases {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.args
			if !tc.noWatch {
				args = withWatch(tc.args...)
			}
			env := newFakeEnv()
			r, err := Resolve(args, env.Env())
			if len(tc.paths) == 0 {
				if err != nil {
					t.Fatalf("Resolve(%q) failed: %v", args, err)
				}
				if r.Command != CommandRun {
					t.Errorf("Command = %q, want run", r.Command)
				}
				return
			}
			if err == nil {
				t.Fatalf("Resolve(%q) succeeded, want errors for %v", args, tc.paths)
			}
			errs := flatten(err)
			if got := paths(errs); !reflect.DeepEqual(got, tc.paths) {
				t.Fatalf("error paths = %q, want %q\nerrors: %v", got, tc.paths, err)
			}
			if tc.msg != "" && !strings.Contains(errs[0].Error(), tc.msg) {
				t.Errorf("first error %q does not contain %q", errs[0], tc.msg)
			}
			for _, e := range errs {
				if e.Path == "" || e.Msg == "" {
					t.Errorf("error without path or message: %#v", e)
				}
			}
		})
	}
}

func TestEmptyListEntriesAreInvalid(t *testing.T) {
	cfg := Default()
	cfg.Watch.ImageContains = []string{"ok", ""}
	cfg.Exclude.ImageContains = []string{"", "ok"}
	cfg.Exclude.ArgvContains = []string{"ok", "ok", ""}
	cfg.Capture.Argv = true
	cfg.Kill.Strings = []string{"", ""}
	cfg.Kill.Regex = []string{"ok", ""}
	cfg.Kill.Fields = []string{"image", ""}
	want := []string{
		"watch.image_contains[1]",
		"exclude.image_contains[0]",
		"exclude.argv_contains[2]",
		"kill.fields[1]",
		"kill.strings[0]",
		"kill.strings[1]",
		"kill.regex[1]",
	}
	var got []string
	for _, e := range validate(&cfg, true) {
		got = append(got, e.Path)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %q, want %q", got, want)
	}
}

func TestErrorsAreOrderedByKeyAndIndex(t *testing.T) {
	cfg := Default()
	cfg.Watch.ImageContains = []string{"", "bad\xff", "", "nul\x00"}
	cfg.Kill.Enabled = true
	cfg.Kill.Fields = []string{"image", "bogus", "argv", ""}
	cfg.Outputs.File.KeepFiles = 0
	want := []string{
		"watch.image_contains[0]", "watch.image_contains[1]", "watch.image_contains[2]", "watch.image_contains[3]",
		"kill.enabled", "kill.fields[1]", "kill.fields[2]", "kill.fields[3]",
		"outputs.file.keep_files",
	}
	if got := paths(validate(&cfg, true)); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %q\nwant   %q", got, want)
	}
}

func TestStringsMustBeUTF8AndNULFree(t *testing.T) {
	cfg := Default()
	cfg.Watch.ImageContains = []string{"ok", "bad\xff"}
	cfg.Kill.Strings = []string{"nul\x00byte"}
	cfg.Outputs.File.Path = "/tmp/a\x00b"
	errs := validate(&cfg, true)
	want := []string{"watch.image_contains[1]", "kill.strings[0]", "outputs.file.path"}
	if got := paths(errs); !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %q, want %q", got, want)
	}
	for _, e := range errs {
		if strings.Contains(e.Msg, "\xff") {
			t.Errorf("message echoes the invalid value: %q", e.Msg)
		}
	}
}

func TestUnsupportedConfigVersion(t *testing.T) {
	cfg := Default()
	cfg.ConfigVersion = 2
	wantOneError(t, validate(&cfg, false), "config_version", "unsupported version 2")
}

func TestWebhookErrorsNeverEchoTheURL(t *testing.T) {
	for _, raw := range []string{
		"https://user:SECRETPW@collector.example.net/x?token=SECRETTOKEN#SECRETFRAG",
		"ftp://collector.example.net/x?token=SECRETTOKEN",
		"https://collector.example.net:99999/x?token=SECRETTOKEN",
		"https://collector.example.net/x?token=SECRETTOKEN a",
		"https://-bad.example/x?token=SECRETTOKEN",
		"https://collector.example.net/%zz?token=SECRETTOKEN",
		"https:SECRETTOKEN",
	} {
		env := newFakeEnv()
		errs := resolveErrors(t, env, withWatch("--webhook-url", raw)...)
		for _, e := range errs {
			if strings.Contains(e.Error(), "SECRET") {
				t.Errorf("error for %q echoes a secret: %v", raw, e)
			}
		}
	}
}

func TestTokenEnvErrorNeverEchoesTheValue(t *testing.T) {
	const secret = "s3cr3t-token-value"
	env := newFakeEnv()
	errs := resolveErrors(t, env, withWatch("--webhook-url", "https://collector.example.net/x", "--webhook-token-env", secret)...)
	wantOneError(t, errs, "outputs.webhook.token_env", "name of an environment variable")
	// The message is about a name that is not a valid variable name; it
	// must not repeat it because it may be the token itself.
	if strings.Contains(errs[0].Error(), secret) {
		t.Errorf("error echoes the token_env value: %v", errs[0])
	}
}

func TestCheckHostPort(t *testing.T) {
	valid := []string{
		"192.0.2.10:9000", "collector.example.net:9000", "[2001:db8::10]:9000", "[::1]:1", "localhost:65535",
		"a.b.c.d.example:80", "host-1.example.com.:80", "my_service.internal:8080", "[fe80::1%eth0]:9000",
		"[::ffff:192.0.2.1]:9000", "xn--mnchen-3ya.example:9000", "1host.example:80",
	}
	for _, a := range valid {
		if msg := checkHostPort(a); msg != "" {
			t.Errorf("checkHostPort(%q) = %q, want valid", a, msg)
		}
	}
	invalid := []string{
		"", "host", "host:", ":80", "host:0", "host:65536", "host:-1", "host:+80", "host:0x50", "host:http",
		"2001:db8::10:9000", "::1", "[::1]", "[::1]:", "[::1", "::1]:80", "tcp://host:80", "host:80:90",
		"[host]:80", "[1.2.3.4]:80", "1.2.3:80", "256.0.0.1:80", "1234:80", "host name:80", "-a.example:80",
		"a-.example:80", "a..example:80", ".example:80", "exa$mple:80", "é.example:80",
		strings.Repeat("a", 64) + ".example:80", strings.Repeat("a.", 130) + "example:80",
	}
	for _, a := range invalid {
		if msg := checkHostPort(a); msg == "" {
			t.Errorf("checkHostPort(%q) accepted an invalid address", a)
		}
	}
}

func TestCompileRegex(t *testing.T) {
	k := KillConfig{Regex: []string{`^(useradd|usermod)$`, `(?i)curl`}}
	res, err := k.CompileRegex()
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || !res[0].MatchString("useradd") || res[0].MatchString("sh -c useradd") || !res[1].MatchString("CURL") {
		t.Errorf("compiled expressions behave unexpectedly: %v", res)
	}
	if _, err := (KillConfig{Regex: []string{"ok", "("}}).CompileRegex(); err == nil || !strings.Contains(err.Error(), "kill.regex[1]") {
		t.Errorf("CompileRegex error = %v, want the index of the bad expression", err)
	}
}

func TestErrorFormatting(t *testing.T) {
	tests := []struct {
		err  *Error
		want string
	}{
		{&Error{Path: "kill.regex[2]", Msg: "bad"}, "kill.regex[2]: bad"},
		{&Error{Path: "kill.regex[2]", Msg: "bad", File: "/etc/pw.yaml", Line: 14}, "/etc/pw.yaml:14: kill.regex[2]: bad"},
		{&Error{Path: "kill.regex[2]", Msg: "bad", File: "/etc/pw.yaml"}, "/etc/pw.yaml: kill.regex[2]: bad"},
		{&Error{Path: "delivery.queue_size", Msg: "bad", Flag: "--queue-size"}, "delivery.queue_size: bad (set by flag --queue-size)"},
		{&Error{Path: "--queue-size", Msg: "invalid integer value"}, "--queue-size: invalid integer value"},
		{&Error{Msg: "invalid YAML: x", File: "/etc/pw.yaml", Line: 3}, "/etc/pw.yaml:3: invalid YAML: x"},
		{&Error{Msg: "empty", File: "/etc/pw.yaml"}, "/etc/pw.yaml: empty"},
		{&Error{Msg: "no cwd"}, "no cwd"},
	}
	for _, tc := range tests {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}

func TestErrorsAsThroughJoin(t *testing.T) {
	env := newFakeEnv()
	_, err := Resolve(withWatch("--watch-max-depth", "-1", "--log-keep-files", "0"), env.Env())
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As failed for %T: %v", err, err)
	}
	if ce.Path != "watch.max_depth" {
		t.Errorf("errors.As found %q first, want the first error in configuration order", ce.Path)
	}
	if n := len(flatten(err)); n != 2 {
		t.Errorf("flatten found %d errors, want 2", n)
	}
	if lines := strings.Count(err.Error(), "\n"); lines != 1 {
		t.Errorf("joined error has %d newlines, want one line per error: %q", lines, err)
	}

	// A single problem is not wrapped.
	_, err = Resolve(withWatch("--log-keep-files", "0"), env.Env())
	if _, ok := err.(*Error); !ok {
		t.Errorf("single problem returned %T, want *Error", err)
	}
}
