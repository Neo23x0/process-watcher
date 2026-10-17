package config

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// checkRoundTrip asserts the central property of print-config: whatever the
// loader accepts prints as YAML that loads again to the identical Config.
// The webhook URL is the one value that is printed redacted (no path, no
// query values, no credentials); it must load and then equals the redacted form.
func checkRoundTrip(t *testing.T, r *Resolved) {
	t.Helper()
	if r.Command == CommandHelp || r.Command == CommandVersion {
		return // no configuration was resolved
	}
	var out bytes.Buffer
	if err := PrintConfig(&out, r); err != nil {
		t.Fatalf("PrintConfig: %v", err)
	}
	env := newFakeEnv()
	env.cwd = "/work"
	if r.Cwd != "" {
		env.cwd = r.Cwd
	}
	env.cwdFile(out.String())
	again, err := Resolve([]string{"doctor"}, env.Env())
	if err != nil {
		t.Fatalf("printed configuration does not load: %v\n%s", err, out.String())
	}
	want := r.Config
	want.Outputs.Webhook.URL = redactURL(want.Outputs.Webhook.URL)
	if !reflect.DeepEqual(want, again.Config) {
		t.Fatalf("round trip changed the configuration:\n before %+v\n after  %+v\n%s", want, again.Config, out.String())
	}
}

func FuzzYAMLDocument(f *testing.F) {
	for _, s := range []string{base, fullYAML, goldenDefaults, "", "---\n", "{}", "config_version: 1\n---\n",
		"config_version: 1\nkill:\n  regex: ['(']\n", "config_version: 1\nwatch:\n  image_contains: [a, ~]\n",
		`{"config_version": 1, "watch": {"image_contains": ["x"]}}`, "config_version: 1\noutputs:\n  file:\n    path: \"\\0\"\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		env := newFakeEnv().cwdFile(doc)
		r, err := Resolve([]string{"doctor"}, env.Env())
		if err != nil {
			if len(flatten(err)) == 0 {
				t.Fatalf("error of type %T is not a *Error: %v", err, err)
			}
			return
		}
		checkRoundTrip(t, r)
	})
}

func FuzzCommandLine(f *testing.F) {
	for _, args := range [][]string{
		{"--watch-image-contains", "nginx"},
		{"check-config", "--watch-image-contains=a", "--kill-regex", "^x$", "--kill-enabled", "--kill-field", "image"},
		{"--exclude-image-contains=", "doctor"},
		{"--log-file", "a b/c", "--tcp-address", "[::1]:1", "--tcp-tls", "--tcp-ca-file", "ca.pem", "doctor"},
		{"--webhook-url", "https://x.example/h?t=1", "doctor"},
		{"--help"}, {"--version"}, {"bogus"}, {"--config", "/nope"}, {},
	} {
		f.Add(strings.Join(args, "\x1f"))
	}
	f.Fuzz(func(t *testing.T, joined string) {
		args := strings.Split(joined, "\x1f")
		env := newFakeEnv()
		r, err := Resolve(args, env.Env())
		if err != nil {
			var ue *UsageError
			if len(flatten(err)) == 0 && !asUsage(err, &ue) {
				t.Fatalf("error of type %T is neither *Error nor *UsageError: %v", err, err)
			}
			return
		}
		checkRoundTrip(t, r)
	})
}

func asUsage(err error, target **UsageError) bool {
	ue, ok := err.(*UsageError)
	if ok {
		*target = ue
	}
	return ok
}
