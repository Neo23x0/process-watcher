package config

import (
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// specTable is the flag mapping of the requirements, written down independently
// of the implementation.
var specTable = []struct {
	yaml, flag string
	repeatable bool
}{
	{"watch.image_contains", "watch-image-contains", true},
	{"watch.ignore_case", "watch-ignore-case", false},
	{"watch.max_depth", "watch-max-depth", false},
	{"exclude.image_contains", "exclude-image-contains", true},
	{"exclude.argv_contains", "exclude-argv-contains", true},
	{"exclude.scope", "exclude-scope", false},
	{"capture.argv", "capture-argv", false},
	{"kill.enabled", "kill-enabled", false},
	{"kill.dry_run", "kill-dry-run", false},
	{"kill.fields", "kill-field", true},
	{"kill.strings", "kill-string", true},
	{"kill.regex", "kill-regex", true},
	{"outputs.file.path", "log-file", false},
	{"outputs.file.rotate_size_mb", "log-rotate-size-mb", false},
	{"outputs.file.keep_files", "log-keep-files", false},
	{"outputs.file.sync_interval", "log-sync-interval", false},
	{"outputs.tcp.address", "tcp-address", false},
	{"outputs.tcp.tls", "tcp-tls", false},
	{"outputs.tcp.ca_file", "tcp-ca-file", false},
	{"outputs.tcp.server_name", "tcp-server-name", false},
	{"outputs.udp.address", "udp-address", false},
	{"outputs.udp.max_bytes", "udp-max-bytes", false},
	{"outputs.webhook.url", "webhook-url", false},
	{"outputs.webhook.token_env", "webhook-token-env", false},
	{"outputs.webhook.timeout", "webhook-timeout", false},
	{"delivery.queue_size", "queue-size", false},
	{"delivery.connect_timeout", "connect-timeout", false},
	{"delivery.write_timeout", "write-timeout", false},
	{"delivery.max_retries", "max-retries", false},
	{"runtime.ring_buffer_mb", "ring-buffer-mb", false},
	{"runtime.max_processes", "max-processes", false},
	{"runtime.health_interval", "health-interval", false},
	{"runtime.reconcile_interval", "reconcile-interval", false},
	{"runtime.shutdown_timeout", "shutdown-timeout", false},
}

func TestFlagTableMatchesSpecification(t *testing.T) {
	want := map[string]string{}
	for _, s := range specTable {
		want[s.flag] = s.yaml
	}
	got := map[string]string{}
	for _, s := range flagSpecs {
		if prev, dup := got[s.Name]; dup {
			t.Errorf("flag --%s is bound twice (%s and %s)", s.Name, prev, s.Key)
		}
		got[s.Name] = s.Key
	}
	if !reflect.DeepEqual(got, want) {
		for f, k := range want {
			if got[f] != k {
				t.Errorf("--%s is bound to %q, want %q", f, got[f], k)
			}
		}
		for f, k := range got {
			if _, ok := want[f]; !ok {
				t.Errorf("--%s (%s) is not in the specification", f, k)
			}
		}
	}
	if len(flagSpecs) != len(specTable) {
		t.Errorf("%d flags, want %d", len(flagSpecs), len(specTable))
	}
}

func TestEveryYAMLLeafHasExactlyOneFlag(t *testing.T) {
	cfg := Default()
	flagged := map[string]int{}
	for _, s := range flagSpecs {
		flagged[s.Key]++
	}
	for _, l := range leaves(&cfg) {
		if l.Key == "config_version" {
			if flagged[l.Key] != 0 {
				t.Errorf("config_version must not have a flag")
			}
			continue
		}
		if flagged[l.Key] != 1 {
			t.Errorf("YAML key %s has %d flags, want 1", l.Key, flagged[l.Key])
		}
		delete(flagged, l.Key)
	}
	for k := range flagged {
		t.Errorf("flag bound to %s, which is not a YAML key", k)
	}
}

// Every flag changes exactly its own leaf, in both spellings.
func TestFlagsBindToTheirLeaf(t *testing.T) {
	for _, s := range specTable {
		for _, dash := range []string{"--", "-"} {
			def := Default()
			defVal := leafMap(&def)[s.yaml]
			var args []string
			switch k, _ := kindOf(defVal.Type()); k {
			case kindBool:
				args = []string{dash + s.flag + "=" + strconv.FormatBool(!defVal.Bool())}
			case kindInt:
				args = []string{dash + s.flag + "=" + strconv.FormatInt(defVal.Int()+1, 10)}
			case kindDuration:
				args = []string{dash + s.flag, (time.Duration(defVal.Int()) + 3*time.Second).String()}
			case kindString:
				args = []string{dash + s.flag, "value-for-" + s.flag}
			case kindList:
				args = []string{dash + s.flag, "first", dash + s.flag + "=second"}
			}
			cl, err := parseArgs(args)
			if err != nil {
				t.Fatalf("%q: %v", args, err)
			}
			cfg := Default()
			origins := map[string]origin{}
			if errs := applyFlags(&cfg, cl, origins); len(errs) != 0 {
				t.Fatalf("%q: %v", args, errs)
			}
			before, after := leafMap(&def), leafMap(&cfg)
			for key, v := range after {
				changed := !reflect.DeepEqual(v.Interface(), before[key].Interface())
				if changed != (key == s.yaml) {
					t.Errorf("%q: leaf %s changed = %v", args, key, changed)
				}
			}
			if o := origins[s.yaml]; o.flag != "--"+s.flag {
				t.Errorf("%q: origin of %s = %+v", args, s.yaml, o)
			}
			if (s.repeatable) != (defVal.Kind() == reflect.Slice) {
				t.Errorf("--%s: repeatable in the specification = %v, but the leaf is a %v", s.flag, s.repeatable, defVal.Kind())
			}
		}
	}
}

func TestBooleanFlagsNeedNoValue(t *testing.T) {
	for _, name := range []string{"watch-ignore-case", "capture-argv", "kill-enabled", "kill-dry-run", "tcp-tls"} {
		cl, err := parseArgs([]string{"--" + name})
		if err != nil {
			t.Fatalf("--%s: %v", name, err)
		}
		cfg := Default()
		if errs := applyFlags(&cfg, cl, map[string]origin{}); len(errs) != 0 {
			t.Fatal(errs)
		}
		for _, s := range flagSpecs {
			if s.Name == name && !leafMap(&cfg)[s.Key].Bool() {
				t.Errorf("--%s alone did not set %s to true", name, s.Key)
			}
		}
	}
}

func TestUsageMentionsEveryFlag(t *testing.T) {
	usage := Usage()
	for _, s := range specTable {
		if !strings.Contains(usage, "--"+s.flag) {
			t.Errorf("Usage does not mention --%s", s.flag)
		}
		if !strings.Contains(usage, "YAML key: "+s.yaml+";") {
			t.Errorf("Usage does not mention the YAML key %s of --%s", s.yaml, s.flag)
		}
	}
	for _, want := range []string{"--config", "-h, --help", "--version"} {
		if !strings.Contains(usage, want) {
			t.Errorf("Usage does not mention %s", want)
		}
	}
}

func TestUsageShowsDefaultsAndRepeatability(t *testing.T) {
	usage := Usage()
	def := Default()
	for _, s := range specTable {
		block := flagBlock(usage, s.flag)
		if block == "" {
			t.Errorf("no help block for --%s", s.flag)
			continue
		}
		if got := strings.Contains(block, "repeatable"); got != s.repeatable {
			t.Errorf("--%s: help says repeatable = %v, want %v", s.flag, got, s.repeatable)
		}
		if !strings.Contains(block, "default: ") {
			t.Errorf("--%s: help shows no default", s.flag)
		}
		v := leafMap(&def)[s.yaml]
		switch k, _ := kindOf(v.Type()); k {
		case kindInt:
			if want := "default: " + strconv.FormatInt(v.Int(), 10); !strings.Contains(block, want) {
				t.Errorf("--%s: help lacks %q:\n%s", s.flag, want, block)
			}
		case kindBool:
			if want := "default: " + strconv.FormatBool(v.Bool()); !strings.Contains(block, want) {
				t.Errorf("--%s: help lacks %q", s.flag, want)
			}
		case kindString:
			if v.String() != "" && !strings.Contains(block, "default: "+v.String()) {
				t.Errorf("--%s: help lacks the default %q", s.flag, v.String())
			}
		}
	}
	for flagName, want := range map[string]string{
		"log-sync-interval":    "default: 1s",
		"health-interval":      "default: 60s",
		"webhook-timeout":      "default: 10s",
		"kill-field":           "default: image",
		"exclude-scope":        "default: remote",
		"log-file":             "default: ./process-watcher.jsonl",
		"udp-max-bytes":        "default: 8192",
		"watch-image-contains": "default: none, required",
	} {
		if block := flagBlock(usage, flagName); !strings.Contains(block, want) {
			t.Errorf("--%s help lacks %q:\n%s", flagName, want, block)
		}
	}
}

// flagBlock returns the help lines of one flag.
func flagBlock(usage, name string) string {
	lines := strings.Split(usage, "\n")
	heading := regexp.MustCompile(`^  --` + regexp.QuoteMeta(name) + `( [A-Z:]+|\[=BOOL\])$`)
	for i, l := range lines {
		if !heading.MatchString(l) {
			continue
		}
		var b []string
		for _, l2 := range lines[i+1:] {
			if !strings.HasPrefix(l2, "        ") {
				break
			}
			b = append(b, l2)
		}
		return strings.Join(b, "\n")
	}
	return ""
}

func TestUsageContent(t *testing.T) {
	usage := Usage()
	must := func(what string, fragments ...string) {
		t.Helper()
		for _, f := range fragments {
			if !strings.Contains(usage, f) {
				t.Errorf("Usage lacks %s: %q", what, f)
			}
		}
	}
	must("the synopsis", "process-watcher [run] [flags]", "check-config [flags]", "print-config [flags]", "doctor [flags]", "--help | -h", "--version")
	must("MiB units", "MiB", "1 048 576 bytes", "_mb")
	must("exit codes", "Exit codes:", "  0  success", "  1  runtime error", "  2  configuration or usage error", "  3  unsupported platform or missing collector prerequisites")
	must("the search order", "1. --config PATH", "2. ./process-watcher.yaml in the working directory", "3. process-watcher.yaml next to the real binary", "4. the built-in defaults")
	must("the precedence", "built-in defaults < YAML file < explicitly set flags")
	must("relative path semantics", "resolved", "working directory of the invocation")
	must("list flag semantics", "replace the entire YAML list", "single", "clears the list", "Commas are ordinary characters")
	must("boolean flag syntax", "--flag=false")
	must("the duration syntax", "Go syntax")
	must("config_version", "config_version: 1")
	must("image matching", "file name of the program that is really executed", "interpreter", "./deploy.sh")
	must("the kill note", "never send signals", "reaction after detection, not preventive blocking", "SIGKILL", "(?i)", "RE2", "capture-argv=true")
	must("check-config guarantees", "attach no BPF programs", "create no output files", "contact no remote")
	must("the doctor rule", "doctor needs no watch pattern")

	// Exactly the three examples, including the one-liner of the kill specification.
	examples := usage[strings.Index(usage, "Examples:"):]
	if n := strings.Count(examples, "\n  # "); n != 3 {
		t.Errorf("%d examples, want 3:\n%s", n, examples)
	}
	if n := strings.Count(examples, "sudo ./process-watcher"); n != 3 {
		t.Errorf("%d command lines, want 3", n)
	}
	for _, want := range []string{
		"--watch-image-contains nginx --log-file /var/log/process-watcher/events.jsonl",
		"--tcp-address collector.example.net:9000 --udp-address 192.0.2.20:9001 --webhook-url https://collector.example.net/hooks/processes",
		"sudo ./process-watcher --watch-image-contains nginx --capture-argv=true --kill-enabled=true --kill-field image --kill-field argv --kill-string demo-long-running-helper --kill-regex '^(useradd|usermod)$'",
	} {
		if !strings.Contains(examples, want) {
			t.Errorf("examples lack %q", want)
		}
	}

	// The note belongs to the kill section.
	kill := strings.Index(usage, "Kill flags:")
	next := strings.Index(usage, "Local log file flags:")
	note := strings.Index(usage, "never send signals. Strings and regular expressions")
	if kill < 0 || next < 0 || note < kill || note > next {
		t.Errorf("kill note is not inside the kill section (kill %d, note %d, next %d)", kill, note, next)
	}
}

func TestUsageSectionsAndLayout(t *testing.T) {
	usage := Usage()
	var order []string
	for _, l := range strings.Split(usage, "\n") {
		if strings.HasSuffix(l, " flags:") {
			order = append(order, strings.TrimSuffix(l, " flags:"))
		}
	}
	want := []string{"General", "Watch", "Exclude", "Capture", "Kill", "Local log file", "TCP output", "UDP output", "Webhook output", "Delivery", "Runtime"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("sections = %q, want %q", order, want)
	}
	// Each flag appears in the section of its YAML key.
	sections := map[string]string{"watch": "Watch", "exclude": "Exclude", "capture": "Capture", "kill": "Kill",
		"outputs.file": "Local log file", "outputs.tcp": "TCP output", "outputs.udp": "UDP output", "outputs.webhook": "Webhook output",
		"delivery": "Delivery", "runtime": "Runtime"}
	for _, s := range flagSpecs {
		prefix := s.Key[:strings.LastIndex(s.Key, ".")]
		if sections[prefix] != s.Section {
			t.Errorf("--%s (%s) is in the %q section, want %q", s.Name, s.Key, s.Section, sections[prefix])
		}
	}
	for i, l := range strings.Split(usage, "\n") {
		if strings.HasPrefix(l, "  sudo ") || strings.HasPrefix(l, "  ./process-watcher") {
			continue // example command lines are long by nature
		}
		if len(l) > 100 {
			t.Errorf("line %d is %d characters long: %q", i+1, len(l), l)
		}
		if strings.TrimRight(l, " ") != l {
			t.Errorf("line %d has trailing spaces", i+1)
		}
	}
	if !strings.HasSuffix(usage, "\n") || strings.HasSuffix(usage, "\n\n") {
		t.Error("usage must end with exactly one newline")
	}
}

func TestUsageNumbersMatchTheRules(t *testing.T) {
	usage := Usage()
	for _, n := range []int{maxRotateSizeMB, maxKeepFiles, minUDPBytes, maxUDPBytes, maxQueueSize, maxRingBufferMB, maxProcesses} {
		if !strings.Contains(usage, strconv.Itoa(n)) {
			t.Errorf("usage does not mention the limit %d", n)
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("one two three four five six", 10)
	want := []string{"one two", "three four", "five six"}
	if !slices.Equal(got, want) {
		t.Errorf("wrap = %q, want %q", got, want)
	}
	if got := wrap("", 10); len(got) != 0 {
		t.Errorf("wrap of nothing = %q", got)
	}
	if got := wrap("averyveryverylongword x", 5); !slices.Equal(got, []string{"averyveryverylongword", "x"}) {
		t.Errorf("wrap with a long word = %q", got)
	}
}
