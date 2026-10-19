// Package installer tests the one-line installer of the PHP kit
// (emerging-threats/php-rce-october-26/install.sh) without a network, without root and without PHP.
//
// The script reads the process list from the directory named by PW_PROC (/proc by default), so every
// test builds a fake /proc: one directory per process holding an exe link, and a maps file where mod_php
// has to be recognized. Only --plan is run here (it detects and prints, and changes nothing); the download,
// the checksum, the start and the stop are exercised against a real kernel by the PHP lab
// (tests/php/lab/scenarios/installer.sh).
package installer

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/config"
)

var kit = filepath.Join("..", "..", "emerging-threats", "php-rce-october-26")

// proc is one fake process.
type proc struct {
	exe  string // what readlink /proc/PID/exe says
	maps string // content of /proc/PID/maps; only mod_php detection reads it
}

func fakeProc(t *testing.T, procs ...proc) string {
	t.Helper()
	dir := t.TempDir()
	for i, p := range procs {
		d := filepath.Join(dir, strconv.Itoa(100+i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if p.exe != "" {
			if err := os.Symlink(p.exe, filepath.Join(d, "exe")); err != nil {
				t.Fatal(err)
			}
		}
		if p.maps != "" {
			if err := os.WriteFile(filepath.Join(d, "maps"), []byte(p.maps), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

type result struct {
	out  string
	code int
}

// run starts the script with a clean environment of its own.
func run(t *testing.T, procDir string, args ...string) result {
	t.Helper()
	script, err := filepath.Abs(filepath.Join(kit, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), "PW_PROC="+procDir, "PW_INSTALL_DIR="+filepath.Join(t.TempDir(), "opt"), "PW_VERSION=v9.9.9")
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{string(out), code}
}

// field returns the value of a labelled line of the plan ("  watching       php-fpm").
func field(out, label string) string {
	m := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(label) + ` +(.*)$`).FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

const libphp = "7f1c00000000-7f1c00800000 r-xp 00000000 00:2e 1234 /usr/lib/apache2/modules/libphp8.4.so\n"

func TestDetectionChoosesWhatToWatchAndTheConfiguration(t *testing.T) {
	nginx := proc{exe: "/usr/sbin/nginx"}
	sshd := proc{exe: "/usr/sbin/sshd"}
	cases := []struct {
		name     string
		procs    []proc
		watch    string // the "watching" line
		config   string // the configuration of the release, "" when nothing is found
		inConfig bool   // every watched name is in the watch list of that configuration itself
	}{
		{"PHP-FPM on Debian", []proc{nginx, {exe: "/usr/sbin/php-fpm8.4"}}, "php-fpm", "php-fpm-observe", true},
		{"PHP-FPM whose binary was replaced by an upgrade", []proc{{exe: "/usr/sbin/php-fpm8.4 (deleted)"}}, "php-fpm", "php-fpm-observe", true},
		{"PHP-FPM on Alpine", []proc{{exe: "/usr/sbin/php-fpm83"}}, "php-fpm", "php-fpm-observe", true},
		{"PHP-FPM of the official image", []proc{{exe: "/usr/local/sbin/php-fpm"}}, "php-fpm", "php-fpm-observe", true},
		{"mod_php on Debian", []proc{sshd, {exe: "/usr/sbin/apache2", maps: libphp}}, "apache2", "apache-mod-php", true},
		{"mod_php on RHEL", []proc{{exe: "/usr/sbin/httpd", maps: libphp}}, "httpd", "apache-mod-php", true},
		{"Apache in front of PHP-FPM is covered by watching php-fpm", []proc{{exe: "/usr/sbin/apache2", maps: "7f00 r-xp /usr/lib/apache2/modules/mod_proxy_fcgi.so\n"}, {exe: "/usr/sbin/php-fpm8.3"}}, "php-fpm", "php-fpm-observe", true},
		{"Apache without PHP", []proc{{exe: "/usr/sbin/apache2", maps: "7f00 r-xp /lib/libc.so.6\n"}}, "nothing", "", false},
		{"php-cgi", []proc{{exe: "/usr/bin/php-cgi8.4"}}, "php-cgi", "php-cgi", true},
		{"PHP CLI, versioned", []proc{{exe: "/usr/bin/php8.4"}}, "php8.", "php-cli-workers", true},
		{"PHP CLI of an older version", []proc{{exe: "/usr/bin/php7.4"}}, "php7.", "php-cli-workers", false},
		{"PHP CLI, unversioned", []proc{{exe: "/usr/local/bin/php"}}, "php", "php-cli-workers", false},
		{"PHP CLI without a dot in its version", []proc{{exe: "/usr/bin/php83"}}, "php83", "php-cli-workers", false},
		{"every kind at once is watched together", []proc{{exe: "/usr/bin/php8.4"}, {exe: "/usr/bin/php-cgi8.4"}, {exe: "/usr/sbin/apache2", maps: libphp}, {exe: "/usr/sbin/php-fpm8.4"}}, "php-fpm apache2 php-cgi php8.", "php-fpm-observe", false},
		{"nothing PHP", []proc{nginx, sshd}, "nothing", "", false},
		{"names that only look like PHP are left alone", []proc{{exe: "/usr/bin/phpize"}, {exe: "/usr/bin/phpdbg"}, {exe: "/usr/bin/php-config"}}, "nothing", "", false},
		{"a kernel thread without an exe link", []proc{{}, {exe: "/usr/sbin/php-fpm8.4"}}, "php-fpm", "php-fpm-observe", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, fakeProc(t, tc.procs...), "--plan")
			if r.code != 0 {
				t.Fatalf("exit %d:\n%s", r.code, r.out)
			}
			if got := field(r.out, "watching"); got != tc.watch {
				t.Errorf("watching %q, want %q\n%s", got, tc.watch, r.out)
			}
			conf := field(r.out, "configuration")
			if tc.config == "" {
				if conf != "none" || !strings.Contains(r.out, "A real run would stop here") {
					t.Errorf("nothing found, but the plan says %q\n%s", conf, r.out)
				}
				return
			}
			if !strings.HasPrefix(conf, "php/"+tc.config+".yaml (observe only, nothing is killed)") {
				t.Errorf("configuration %q, want php/%s.yaml\n%s", conf, tc.config, r.out)
			}
			if !strings.Contains(r.out, "Plan only: nothing was changed.") {
				t.Errorf("no statement that nothing was changed\n%s", r.out)
			}
			// The names the script derives must be ones the configuration of the release itself lists.
			cfg := load(t, tc.config)
			if tc.inConfig {
				for _, w := range strings.Fields(tc.watch) {
					if !slices.Contains(cfg.Watch.ImageContains, w) {
						t.Errorf("the script watches %q, php/%s.yaml lists only %v", w, tc.config, cfg.Watch.ImageContains)
					}
				}
			}
		})
	}
}

func load(t *testing.T, name string) config.Config {
	t.Helper()
	r, err := config.Resolve([]string{"check-config", "--config", filepath.Join(kit, "configs", name+".yaml")}, config.OSEnv())
	if err != nil {
		t.Fatalf("configs/%s.yaml: %v", name, err)
	}
	return r.Config
}

func TestExplicitChoicesReplaceDetection(t *testing.T) {
	fpm := fakeProc(t, proc{exe: "/usr/sbin/php-fpm8.4"})
	t.Run("--watch replaces what was found", func(t *testing.T) {
		r := run(t, fpm, "--plan", "--watch", "php-cgi", "--watch", "my-php")
		if field(r.out, "watching") != "php-cgi my-php" || !strings.Contains(field(r.out, "configuration"), "with your --watch list") {
			t.Errorf("%s", r.out)
		}
	})
	t.Run("--watch works when nothing was found", func(t *testing.T) {
		r := run(t, fakeProc(t, proc{exe: "/usr/sbin/sshd"}), "--plan", "--watch", "php-fpm")
		if field(r.out, "watching") != "php-fpm" || strings.Contains(r.out, "would stop here") {
			t.Errorf("%s", r.out)
		}
	})
	t.Run("--config uses the list of that configuration", func(t *testing.T) {
		r := run(t, fpm, "--plan", "--config", "php-fpm-dry-run")
		if field(r.out, "configuration") != "php/php-fpm-dry-run.yaml" || field(r.out, "watching") != "as listed in the configuration" {
			t.Errorf("%s", r.out)
		}
	})
	t.Run("--config accepts the file name and works without a PHP process", func(t *testing.T) {
		r := run(t, fakeProc(t), "--plan", "--config", "php-fpm-dry-run.yaml")
		if field(r.out, "configuration") != "php/php-fpm-dry-run.yaml" || strings.Contains(r.out, "would stop here") {
			t.Errorf("%s", r.out)
		}
	})
	t.Run("--version is shown in the plan", func(t *testing.T) {
		r := run(t, fpm, "--plan", "--version", "v1.2.3")
		if field(r.out, "version") != "v1.2.3" || !strings.Contains(field(r.out, "download"), "/v1.2.3/process-watcher_v1.2.3_linux_") {
			t.Errorf("%s", r.out)
		}
	})
}

func TestBadInputIsRefusedBeforeAnythingHappens(t *testing.T) {
	empty := fakeProc(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--version", "v1.0.0;rm -rf /"}, "invalid value for --version"},
		{[]string{"--version", "../../etc"}, "invalid value for --version"},
		{[]string{"--watch", "a b"}, "invalid value for --watch"},
		{[]string{"--config", "../../etc/passwd"}, "invalid value for --config"},
		{[]string{"--config", ""}, "invalid value for --config"},
		{[]string{"--version"}, "needs a value"},
		{[]string{"--frobnicate"}, "unknown option"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			r := run(t, empty, append([]string{"--plan"}, tc.args...)...)
			if r.code == 0 || !strings.Contains(r.out, tc.want) {
				t.Errorf("exit %d, want a refusal mentioning %q:\n%s", r.code, tc.want, r.out)
			}
		})
	}
	if r := run(t, empty, "--help"); r.code != 0 || !strings.Contains(r.out, "Observe only") {
		t.Errorf("--help: exit %d\n%s", r.code, r.out)
	}
}

// A plan must not touch the machine: no download, nothing written below the install directory.
func TestPlanDoesNotTouchTheMachine(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "curl-was-called")
	shim := "#!/bin/sh\ntouch " + marker + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(t.TempDir(), "opt")
	script, _ := filepath.Abs(filepath.Join(kit, "install.sh"))
	cmd := exec.Command("sh", script, "--plan")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "PW_PROC="+fakeProc(t, proc{exe: "/usr/sbin/php-fpm8.4"}), "PW_INSTALL_DIR="+install)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the plan called curl")
	}
	if _, err := os.Stat(install); err == nil {
		t.Error("the plan created the install directory")
	}
}

// The script starts configurations by name and refuses a real kill without --allow-kill by reading the
// configuration (the lab test checks that refusal against the real script); this pins down which shipped
// configuration that is, so a new configuration that really kills cannot appear unnoticed.
func TestOnlyOneShippedConfigurationReallyKills(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(kit, "configs", "*.yaml"))
	if err != nil || len(files) < 7 {
		t.Fatalf("configurations: %v %v", files, err)
	}
	var killing []string
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".yaml")
		if c := load(t, name); c.Kill.Enabled && !c.Kill.DryRun {
			killing = append(killing, name)
		}
	}
	if len(killing) != 1 || killing[0] != "php-fpm-kill" {
		t.Errorf("configurations that really send SIGKILL: %v, want only php-fpm-kill", killing)
	}
}

func TestScriptIsPortableShell(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(kit, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "#!/bin/sh\n") {
		t.Error("the script must start with #!/bin/sh: it runs on Debian (dash), Alpine (busybox) and RHEL (bash)")
	}
	for _, bashism := range []string{"[[ ", "local ", "echo -e", "<<<", "function ", "${!", "declare ", "source ", "=~"} {
		if strings.Contains(text, bashism) {
			t.Errorf("bash-only syntax %q in a script that runs under sh", bashism)
		}
	}
}
