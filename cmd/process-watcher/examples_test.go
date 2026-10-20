package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neo23x0/process-watcher/internal/app"
)

// writeTestCA writes a throwaway self-signed CA certificate and returns its path.
func writeTestCA(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "process-watcher test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "test-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every shipped example configuration must pass the strict loader, so the
// examples cannot rot.
func TestShippedConfigurationsAreValid(t *testing.T) {
	t.Setenv("PROCESS_WATCHER_TOKEN", "not-a-real-token")
	var files []string
	for _, pattern := range []string{
		filepath.Join("..", "..", "examples", "*.yaml"),
		filepath.Join("..", "..", "emerging-threats", "php-rce-october-26", "configs", "*.yaml"),
		filepath.Join("..", "..", "packaging", "config", "*.yaml"),
	} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 7 {
		t.Fatalf("expected the example files, found %v", files)
	}
	ca := writeTestCA(t, t.TempDir())
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			args := []string{"check-config", "--config", f}
			// The remote example names a CA bundle path of the deployment; check-config
			// reads that file, so the test supplies one.
			if b, _ := os.ReadFile(f); strings.Contains(string(b), "ca_file: /") {
				args = append(args, "--tcp-ca-file", ca)
			}
			var out, errb bytes.Buffer
			if code := realMain(args, &out, &errb); code != app.ExitOK {
				t.Fatalf("exit %d: %s%s", code, out.String(), errb.String())
			}
			if !strings.Contains(out.String(), "configuration OK") {
				t.Errorf("output %q", out.String())
			}
		})
	}
}

func TestCommandsAndExitCodes(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "events.jsonl")
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := realMain(args, &out, &errb)
		return code, out.String(), errb.String()
	}

	if code, out, _ := run("--version"); code != 0 || !strings.HasPrefix(out, "process-watcher ") {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, out, _ := run("--help"); code != 0 || !strings.Contains(out, "--kill-regex") || !strings.Contains(out, "--watch-image-contains") {
		t.Errorf("--help: %d", code)
	}
	// Configuration errors are exit code 2 and have no side effects.
	for name, args := range map[string][]string{
		"no watch pattern":          {"--log-file", log},
		"unknown flag":              {"--nope"},
		"unknown subcommand":        {"frobnicate"},
		"argv rule without capture": {"--watch-image-contains", "x", "--kill-enabled=true", "--kill-field", "argv", "--kill-string", "y", "--log-file", log},
	} {
		if code, _, errb := run(args...); code != app.ExitConfig {
			t.Errorf("%s: exit %d, want 2 (%s)", name, code, errb)
		}
	}
	// An unusable CA bundle is a configuration error for check-config as well as
	// for run, and neither leaves a log directory, a log or a lock file behind.
	missingCA := filepath.Join(dir, "no-such-ca.pem")
	logDir := filepath.Join(dir, "never-created")
	for _, cmd := range []string{"check-config", "run"} {
		code, _, errb := run(cmd, "--watch-image-contains", "nginx", "--tcp-address", "collector.example.net:9000", "--tcp-tls",
			"--tcp-ca-file", missingCA, "--log-file", filepath.Join(logDir, "events.jsonl"))
		if code != app.ExitConfig || !strings.Contains(errb, "CA file") || strings.Contains(errb, "output: tcp output") {
			t.Errorf("%s with an unreadable CA file: exit %d, want 2 (%s)", cmd, code, errb)
		}
		if _, err := os.Stat(logDir); err == nil {
			t.Errorf("%s with an unreadable CA file created the log directory", cmd)
		}
	}
	// check-config and print-config never create files and never signal anything.
	code, out, _ := run("check-config", "--watch-image-contains", "nginx", "--capture-argv=true", "--kill-enabled=true", "--kill-field", "argv", "--kill-string", "demo", "--log-file", log)
	if code != 0 || !strings.Contains(out, "never sends a signal") {
		t.Errorf("check-config with kill rules: %d %q", code, out)
	}
	if _, err := os.Stat(log); err == nil {
		t.Error("check-config created the log file")
	}
	code, out, _ = run("print-config", "--watch-image-contains", "nginx", "--kill-enabled=true", "--kill-regex", "^useradd$", "--log-file", log)
	if code != 0 || !strings.Contains(out, "kill:") || !strings.Contains(out, "^useradd$") {
		t.Errorf("print-config: %d\n%s", code, out)
	}
	if _, err := os.Stat(log); err == nil {
		t.Error("print-config created the log file")
	}
}
