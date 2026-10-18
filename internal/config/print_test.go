package config

import (
	"bytes"
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

const goldenDefaults = `# source: built-in defaults
config_version: 1

watch:
  image_contains: [nginx]
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

kill:
  enabled: false
  dry_run: false
  fields: [image]
  strings: []
  regex: []
  spare_root_image: false

outputs:
  file:
    path: /work/process-watcher.jsonl
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

func printString(t *testing.T, r *Resolved) string {
	t.Helper()
	var b bytes.Buffer
	if err := PrintConfig(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestPrintConfigGolden(t *testing.T) {
	r := mustResolve(t, newFakeEnv(), "print-config", "--watch-image-contains", "nginx")
	got := printString(t, r)
	if got != goldenDefaults {
		t.Errorf("print-config output differs from the golden text:\n%s\nwant:\n%s", got, goldenDefaults)
	}
	if again := printString(t, r); again != got {
		t.Errorf("print-config is not deterministic")
	}

	// The documented section order, kill after capture.
	for _, pair := range [][2]string{{"\ncapture:", "\nkill:"}, {"\nkill:", "\noutputs:"}, {"\nwatch:", "\nexclude:"}, {"\ndelivery:", "\nruntime:"}} {
		if strings.Index(got, pair[0]) > strings.Index(got, pair[1]) {
			t.Errorf("section %q must come before %q", strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1]))
		}
	}
}

func TestPrintConfigNamesTheSource(t *testing.T) {
	env := newFakeEnv().file("/etc/pw/config.yaml", base)
	r := mustResolve(t, env, "--config", "/etc/pw/config.yaml", "print-config")
	out := printString(t, r)
	if first, _, _ := strings.Cut(out, "\n"); first != "# source: /etc/pw/config.yaml" {
		t.Errorf("first line = %q", first)
	}

	// A hostile file name must not break out of the comment.
	r.SourceFile = "/tmp/x\nwatch:\n  image_contains: [evil]\n"
	out = printString(t, r)
	if strings.Count(out, "\n# ") != 0 || strings.Contains(out, "\nwatch:\n  image_contains: [evil]") {
		t.Errorf("source file name injected YAML:\n%s", out)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output with a hostile source name is not YAML: %v", err)
	}
}

// fullYAML sets every setting to a value that differs from the default and
// uses strings that need quoting.
const fullYAML = `config_version: 1
watch:
  image_contains: ["nginx", "apache 2", "sh\"ell", "gr\u00fc\u00dfe", "tab\there", "true", "123", "-dash", "#hash", "a: b"]
  ignore_case: true
  max_depth: 3
exclude:
  image_contains: [helper, "x y"]
  argv_contains: ["--password=", "back\\slash", "multi\nline"]
  scope: all
capture:
  argv: true
  argv_max_args: 100
  argv_max_bytes: 16000
kill:
  enabled: true
  dry_run: true
  fields: [image, image_path, argv, argv]
  strings: ["demo-long-running-helper", "multi\nline", " lead", "trail ", "'single'", "~"]
  regex: ['^(useradd|usermod)$', '(?i)\bcurl\b', '"quoted"', '\\']
  spare_root_image: true
outputs:
  file:
    path: /var/log/pw/my events.jsonl
    rotate_size_mb: 250
    keep_files: 9
    sync_interval: 1500ms
  tcp:
    address: "[2001:db8::10]:9000"
    tls: true
    ca_file: /etc/ssl/ca.pem
    server_name: collector.example.net
  udp:
    address: 192.0.2.20:9001
    max_bytes: 1200
  webhook:
    url: https://collector.example.net/hooks/processes
    token_env: PW_TOKEN
    timeout: 90s
delivery:
  queue_size: 500
  connect_timeout: 2s
  write_timeout: 3s
  max_retries: 0
runtime:
  ring_buffer_mb: 64
  max_processes: 1000
  health_interval: 2m
  reconcile_interval: 45s
  shutdown_timeout: 1h
`

func TestPrintConfigRoundTrip(t *testing.T) {
	env := newFakeEnv().cwdFile(fullYAML)
	env.vars["PW_TOKEN"] = "SECRETVALUE"
	first := mustResolve(t, env, "print-config")

	// The document really sets everything to something else than the default.
	def := Default()
	defaults := leafMap(&def)
	for _, l := range leaves(&first.Config) {
		if l.Key != "config_version" && reflect.DeepEqual(l.Val.Interface(), defaults[l.Key].Interface()) {
			t.Errorf("fullYAML leaves %s at its default; the round trip would not test it", l.Key)
		}
	}

	out := printString(t, first)
	if strings.Contains(out, "SECRETVALUE") {
		t.Errorf("print-config leaks the token:\n%s", out)
	}
	if !strings.Contains(out, "token_env: PW_TOKEN\n") {
		t.Errorf("token_env is not printed as the variable name:\n%s", out)
	}

	// The printed YAML loads through the strict loader to an identical Config.
	env2 := newFakeEnv().cwdFile(out)
	env2.vars["PW_TOKEN"] = "SECRETVALUE"
	second := mustResolve(t, env2, "print-config")
	// Everything but the webhook URL survives; the URL is printed without its
	// path (chat services keep the secret there) and without query values.
	want := first.Config
	want.Outputs.Webhook.URL = "https://collector.example.net/..."
	if !reflect.DeepEqual(want, second.Config) {
		t.Errorf("round trip changed the configuration:\n want   %+v\n second %+v", want, second.Config)
	}
	if again := printString(t, second); again != out {
		t.Errorf("printing is not idempotent:\n%s\n---\n%s", out, again)
	}
	if first.SourceFile != cfgPath || !strings.HasPrefix(out, "# source: "+cfgPath+"\n") {
		t.Errorf("source file not reported: %q", first.SourceFile)
	}
}

func TestPrintConfigRoundTripWithFlags(t *testing.T) {
	env := newFakeEnv()
	first := mustResolve(t, env, "print-config",
		"--watch-image-contains", "nginx", "--watch-image-contains", "weird \"name\" \\ #1",
		"--exclude-argv-contains", "line1\nline2", "--capture-argv",
		"--kill-regex", `^a\d+$`, "--kill-string", "\t",
		"--log-file", "relative dir/events.jsonl", "--tcp-address", "collector.example.net:9000", "--tcp-tls", "--tcp-ca-file", "ca.pem",
		"--log-sync-interval", "1h30m", "--webhook-timeout", "1500us", "--health-interval", "1m",
		"--webhook-url", "http://10.0.0.1:8080/hook")
	out := printString(t, first)
	second := mustResolve(t, newFakeEnv().cwdFile(out), "print-config")
	want := first.Config
	want.Outputs.Webhook.URL = "http://10.0.0.1:8080/..."
	if !reflect.DeepEqual(want, second.Config) {
		t.Errorf("round trip changed the configuration:\n want   %+v\n second %+v\noutput:\n%s", want, second.Config, out)
	}
	for _, want := range []string{"sync_interval: 5400s", "timeout: 1.5ms", "health_interval: 60s", "path: \"/work/relative dir/events.jsonl\""} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestPrintConfigCoversEveryLeafInOrder(t *testing.T) {
	r := mustResolve(t, newFakeEnv(), "print-config", "--watch-image-contains", "nginx")
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(printString(t, r)), &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	var walk func(n *yaml.Node, prefix string)
	walk = func(n *yaml.Node, prefix string) {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, n.Content[i+1]
			if v.Kind == yaml.MappingNode {
				walk(v, joinKey(prefix, k))
			} else {
				got = append(got, joinKey(prefix, k))
			}
		}
	}
	walk(doc.Content[0], "")
	var want []string
	for _, l := range leaves(&r.Config) {
		want = append(want, l.Key)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("printed keys = %v\nwant %v", got, want)
	}
	if got[0] != "config_version" {
		t.Errorf("first key = %q", got[0])
	}
}

func TestPrintConfigNeverPrintsSecrets(t *testing.T) {
	env := newFakeEnv()
	env.vars["PW_TOKEN"] = "SECRETVALUE"
	r := mustResolve(t, env, "print-config", "--watch-image-contains", "nginx",
		"--webhook-url", "https://collector.example.net/hooks/processes?token=SECRETQUERY&team=blue&flag",
		"--webhook-token-env", "PW_TOKEN")
	out := printString(t, r)
	for _, secret := range []string{"SECRETQUERY", "SECRETVALUE", "blue", "/hooks"} {
		if strings.Contains(out, secret) {
			t.Errorf("output contains %q:\n%s", secret, out)
		}
	}
	if want := `url: "https://collector.example.net/...?token=REDACTED&team=REDACTED&REDACTED"`; !strings.Contains(out, want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
	if !strings.Contains(out, "token_env: PW_TOKEN") {
		t.Errorf("token_env missing:\n%s", out)
	}
	// The redacted output is still a valid configuration.
	env2 := newFakeEnv().cwdFile(out)
	env2.vars["PW_TOKEN"] = "x"
	r2 := mustResolve(t, env2, "print-config")
	if !strings.Contains(r2.Config.Outputs.Webhook.URL, "REDACTED") {
		t.Errorf("reloaded URL = %q", r2.Config.Outputs.Webhook.URL)
	}

	// PrintConfig also protects configurations that were not validated.
	cfg := Default()
	cfg.Outputs.Webhook.URL = "https://user:SECRETPW@collector.example.net/x?t=SECRETQUERY#SECRETFRAG"
	out = printString(t, &Resolved{Config: cfg})
	if strings.Contains(out, "SECRET") {
		t.Errorf("unvalidated configuration leaks secrets:\n%s", out)
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"https://collector.example.net", "https://collector.example.net"},
		{"https://collector.example.net/", "https://collector.example.net/"},
		{"https://collector.example.net/hook", "https://collector.example.net/..."},
		{"https://hooks.chat.example/services/T000/B000/XXXXSECRET", "https://hooks.chat.example/..."},
		{"https://collector.example.net/hook?", "https://collector.example.net/...?"},
		{"https://c.example/h?token=abc", "https://c.example/...?token=REDACTED"},
		{"https://c.example/h?a=1&b=2&a=3", "https://c.example/...?a=REDACTED&b=REDACTED&a=REDACTED"},
		{"https://c.example/h?a=&b", "https://c.example/...?a=REDACTED&REDACTED"},
		{"https://c.example/h?secret", "https://c.example/...?REDACTED"},
		{"https://c.example/h?a=1;b=2", "https://c.example/...?a=REDACTED"},
		{"https://c.example/h?a=b=c", "https://c.example/...?a=REDACTED"},
		{"https://c.example/h?a=1&&b=2", "https://c.example/...?a=REDACTED&&b=REDACTED"},
		{"https://c.example/h?a=1&", "https://c.example/...?a=REDACTED&"},
		{"https://c.example/h?token=REDACTED", "https://c.example/...?token=REDACTED"},
		{"https://user:pw@c.example/h", "https://REDACTED@c.example/..."},
		{"https://user@c.example:8443/h?x=1", "https://REDACTED@c.example:8443/...?x=REDACTED"},
		{"https://c.example/h#frag?x=1", "https://c.example/...#REDACTED"},
		{"https://c.example/h?x=1#frag", "https://c.example/...?x=REDACTED#REDACTED"},
		{"https://c.example/a@b/c", "https://c.example/..."},
		{"https://c.example?x=1", "https://c.example?x=REDACTED"},
		{"not a url?x=1", "not a url?x=REDACTED"},
	}
	for _, tc := range tests {
		if got := redactURL(tc.in); got != tc.want {
			t.Errorf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if again := redactURL(redactURL(tc.in)); again != redactURL(tc.in) {
			t.Errorf("redactURL is not idempotent for %q", tc.in)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{time.Second, "1s"},
		{60 * time.Second, "60s"},
		{30 * time.Second, "30s"},
		{90 * time.Minute, "5400s"},
		{time.Hour, "3600s"},
		{1500 * time.Millisecond, "1500ms"},
		{time.Millisecond, "1ms"},
		{-5 * time.Second, "-5s"},
		{-250 * time.Millisecond, "-250ms"},
		{1500 * time.Microsecond, "1.5ms"},
		{time.Microsecond, "1\u00b5s"},
		{time.Nanosecond, "1ns"},
		{time.Hour + time.Millisecond, "3600001ms"},
		{1<<63 - 1, ""},
	}
	for _, tc := range tests {
		got := formatDuration(tc.d)
		if tc.want != "" && got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
		back, err := time.ParseDuration(got)
		if err != nil || back != tc.d {
			t.Errorf("formatDuration(%v) = %q parses back to %v, %v", tc.d, got, back, err)
		}
	}
}

func TestYAMLStringRoundTrip(t *testing.T) {
	check := func(s string) {
		t.Helper()
		for _, doc := range []string{"v: " + yamlString(s) + "\n", "v: [" + yamlString(s) + ", " + yamlString(s) + "]\n"} {
			var n yaml.Node
			if err := yaml.Unmarshal([]byte(doc), &n); err != nil {
				t.Fatalf("yamlString(%q) = %s is not parsable: %v", s, yamlString(s), err)
			}
			v := n.Content[0].Content[1]
			if v.Kind == yaml.SequenceNode {
				for _, e := range v.Content {
					if e.ShortTag() != "!!str" || e.Value != s {
						t.Fatalf("list element of %q came back as %q (%s)", s, e.Value, e.ShortTag())
					}
				}
				continue
			}
			if v.ShortTag() != "!!str" || v.Value != s {
				t.Fatalf("yamlString(%q) = %s came back as %q (%s)", s, yamlString(s), v.Value, v.ShortTag())
			}
		}
	}
	fixed := []string{
		"", " ", "nginx", "true", "True", "TRUE", "false", "null", "Null", "~", "yes", "no", "on", "off", "y", "n", "Y", "N",
		"123", "1.5", "0x10", "1e3", "-1", "+1", ".5", ".inf", ".nan", "1_000", "0o17", "2001-12-14", "12:30:45",
		"-", "- a", "? a", ": a", "a: b", "a #b", "#a", "a,b", "[a]", "{a}", "&a", "*a", "!a", "|", ">", "%a", "@a", "`a`",
		"\"", "'", "\\", "a\"b", "a'b", "a\\b", "line1\nline2", "tab\tsep", "cr\rlf", "nul\x00byte", "del\x7f", "bell\a",
		"\u0085", "\u2028", "\u2029", "\ufeff", "\u202e", "gr\u00fc\u00dfe", "\u65e5\u672c\u8a9e", "\U0001F600", "\U0010FFFF",
		"/usr/bin/nginx", "./relative", "../up", "a b", " lead", "trail ", "a/b-c_d.e", "<<", "=", "---", "...", "%YAML 1.2",
		"^(useradd|usermod)$", `(?i)\bcurl\b`, "$HOME", "C:\\dir",
	}
	for _, s := range fixed {
		check(s)
	}
	// Plain output is only used where it is unambiguous.
	for _, s := range []string{"nginx", "remote", "/var/log/pw/events.jsonl", "my_service.internal", "a-b.c"} {
		if got := yamlString(s); got != s {
			t.Errorf("yamlString(%q) = %q, want the plain form", s, got)
		}
	}
	for _, s := range []string{"true", "Null", "yes", "off", "y", "123", "-a", ".5", "", "a b", "a:b", "a#b", "~"} {
		if got := yamlString(s); got == s {
			t.Errorf("yamlString(%q) kept the plain form", s)
		}
	}

	alphabet := []rune("\"\\'#:,[]{}&*!|>%@` \t\n\r\x00\x7f\u0085\u2028\u2029\ufeff\u00e9\u65e5\U0001F600-?~._/abXY019=<")
	rng := rand.New(rand.NewSource(1))
	for range 5000 {
		n := rng.Intn(14)
		r := make([]rune, n)
		for i := range r {
			r[i] = alphabet[rng.Intn(len(alphabet))]
		}
		check(string(r))
	}
}

func TestPrintConfigErrors(t *testing.T) {
	if err := PrintConfig(&bytes.Buffer{}, nil); err == nil {
		t.Error("PrintConfig(nil) succeeded")
	}
	r := mustResolve(t, newFakeEnv(), "print-config", "--watch-image-contains", "nginx")
	boom := errors.New("disk full")
	if err := PrintConfig(failingWriter{boom}, r); !errors.Is(err, boom) {
		t.Errorf("PrintConfig error = %v, want the writer error", err)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }
