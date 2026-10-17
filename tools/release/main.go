// Command release builds the release archives of process-watcher.
//
//	go run ./tools/release -version v0.1.1 [-out dist/release] [-arch amd64,arm64]
//
// For every architecture it cross-compiles the agent as a static Linux binary,
// checks that the result really is a single self-contained executable (no
// dynamic loader, no shared libraries) and writes two archives with the same
// contents:
//
//	<out>/process-watcher_<version>_linux_<arch>.tar.gz   this version, for pinning
//	<out>/process-watcher_linux_<arch>.tar.gz             the same name in every release
//
// The second name makes https://github.com/<owner>/<repo>/releases/latest/download/process-watcher_linux_<arch>.tar.gz
// work without knowing the version. Each archive has one directory of the same
// name as the archive (so unpacking one never overwrites an unpacked other
// version) with
//
//	process-watcher                              the binary
//	process-watcher.yaml                         the example configuration (the agent finds it next to its binary)
//	LICENSE
//	packaging/install.sh                         installs the binary and the unit; the repository's packaging/ layout
//	packaging/systemd/process-watcher.service    the systemd unit
//	packaging/config/process-watcher.yaml        what install.sh installs as /etc/process-watcher/config.yaml
//
// A file <out>/SHA256SUMS lists every archive.
//
// Archive metadata is fixed (owner root, modification time from
// SOURCE_DATE_EPOCH or the time of the last commit, fixed entry order, no gzip
// timestamp) and the build uses -trimpath without VCS stamping, so the same
// source and Go toolchain give byte-identical archives on every machine: a
// maintainer can rebuild a release locally and compare the checksums.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// target describes one supported architecture.
type target struct {
	goarch  string
	machine elf.Machine
}

// targets are the architectures the eBPF collector supports (the agent refuses
// to start on any other); 32-bit kernels are not supported.
var targets = []target{
	{"amd64", elf.EM_X86_64},
	{"arm64", elf.EM_AARCH64},
}

var versionRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

// checkVersion accepts tags like v0.1.0 and v1.2.3-rc.1.
func checkVersion(v string) error {
	if !versionRE.MatchString(v) {
		return fmt.Errorf("version %q is not of the form vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-PRERELEASE (for example v0.1.0)", v)
	}
	return nil
}

// entry is one file of an archive; a name with slashes lies in a subdirectory.
type entry struct {
	name string
	mode int64
	data []byte
}

// payload is everything an archive holds besides the binary.
type payload struct {
	config        []byte // process-watcher.yaml: the documented example configuration
	license       []byte // LICENSE
	installer     []byte // packaging/install.sh
	unit          []byte // packaging/systemd/process-watcher.service
	serviceConfig []byte // packaging/config/process-watcher.yaml
}

// entries lists the files of an archive in their fixed order.
func (p payload) entries(bin []byte) []entry {
	return []entry{
		{"process-watcher", 0o755, bin},
		{"process-watcher.yaml", 0o644, p.config},
		{"LICENSE", 0o644, p.license},
		{"packaging/install.sh", 0o755, p.installer},
		{"packaging/systemd/process-watcher.service", 0o644, p.unit},
		{"packaging/config/process-watcher.yaml", 0o644, p.serviceConfig},
	}
}

// loadPayload reads the files below root. packaging is the directory with the
// install script, the unit and the service configuration (the layout of the
// repository's packaging/ directory, which install.sh expects next to itself).
func loadPayload(root, config, license, packaging string) (payload, error) {
	read := func(rel string) ([]byte, error) {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("%s is empty", filepath.Join(root, rel))
		}
		return data, nil
	}
	var p payload
	var err error
	for _, f := range []struct {
		dst *[]byte
		rel string
	}{
		{&p.config, config},
		{&p.license, license},
		{&p.installer, filepath.Join(packaging, "install.sh")},
		{&p.unit, filepath.Join(packaging, "systemd", "process-watcher.service")},
		{&p.serviceConfig, filepath.Join(packaging, "config", "process-watcher.yaml")},
	} {
		if *f.dst, err = read(f.rel); err != nil {
			return payload{}, err
		}
	}
	if !bytes.HasPrefix(p.installer, []byte("#!")) {
		return payload{}, fmt.Errorf("%s does not start with a #! line", filepath.Join(root, packaging, "install.sh"))
	}
	return p, nil
}

// archiveNames returns the names (without .tar.gz) of the two archives of one
// architecture: with the version in the name, and without it.
func archiveNames(version, goarch string) []string {
	return []string{
		fmt.Sprintf("process-watcher_%s_linux_%s", version, goarch),
		fmt.Sprintf("process-watcher_linux_%s", goarch),
	}
}

// writeArchive writes a deterministic .tar.gz: one directory, the entries in the
// given order (every subdirectory right before its first file), owner root, the
// same modification time everywhere.
func writeArchive(file, dir string, entries []entry, mtime time.Time) error {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}
	zw.ModTime = time.Time{} // no timestamp in the gzip header
	tw := tar.NewWriter(zw)
	hdr := func(name string, mode int64, size int64, typ byte) *tar.Header {
		return &tar.Header{Typeflag: typ, Name: name, Mode: mode, Size: size, ModTime: mtime, Format: tar.FormatUSTAR}
	}
	if err := tw.WriteHeader(hdr(dir+"/", 0o755, 0, tar.TypeDir)); err != nil {
		return err
	}
	madeDir := map[string]bool{}
	for _, e := range entries {
		for i := 0; i < len(e.name); i++ {
			if e.name[i] != '/' {
				continue
			}
			sub := dir + "/" + e.name[:i+1]
			if madeDir[sub] {
				continue
			}
			madeDir[sub] = true
			if err := tw.WriteHeader(hdr(sub, 0o755, 0, tar.TypeDir)); err != nil {
				return err
			}
		}
		if err := tw.WriteHeader(hdr(dir+"/"+e.name, e.mode, int64(len(e.data)), tar.TypeReg)); err != nil {
			return err
		}
		if _, err := tw.Write(e.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(file, buf.Bytes(), 0o644)
}

// sum is one line of SHA256SUMS.
type sum struct {
	name string // file name
	line string // "<hash>  <name>\n"
}

// sumsLine formats one line of SHA256SUMS ("<hash>  <name>", as sha256sum -c reads it).
func sumsLine(name string, data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]) + "  " + name + "\n"
}

// writeSums writes SHA256SUMS, sorted by file name, and returns its content.
func writeSums(out string, sums []sum) (string, error) {
	sort.Slice(sums, func(i, j int) bool { return sums[i].name < sums[j].name })
	var b strings.Builder
	for _, s := range sums {
		b.WriteString(s.line)
	}
	return b.String(), os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(b.String()), 0o644)
}

// writeArchives writes both archives of one architecture below out and returns
// their SHA256SUMS lines.
func writeArchives(out, version, goarch string, entries []entry, mtime time.Time) ([]sum, error) {
	var sums []sum
	for _, dir := range archiveNames(version, goarch) {
		name := dir + ".tar.gz"
		if err := writeArchive(filepath.Join(out, name), dir, entries, mtime); err != nil {
			return nil, err
		}
		arc, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			return nil, err
		}
		sums = append(sums, sum{name, sumsLine(name, arc)})
	}
	return sums, nil
}

// checkStatic verifies that the file is a single static executable for the
// machine: no interpreter (dynamic loader) and no shared library dependency.
func checkStatic(path string, want elf.Machine) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("%s is not an ELF file: %w", path, err)
	}
	defer f.Close()
	switch {
	case f.Class != elf.ELFCLASS64:
		return fmt.Errorf("%s is not a 64-bit executable (class %v)", path, f.Class)
	case f.Machine != want:
		return fmt.Errorf("%s is built for %v, want %v", path, f.Machine, want)
	case f.Type != elf.ET_EXEC:
		return fmt.Errorf("%s is %v, want a statically linked executable (ET_EXEC)", path, f.Type)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
			return fmt.Errorf("%s is dynamically linked (program header %v)", path, p.Type)
		}
	}
	if libs, err := f.ImportedLibraries(); err != nil || len(libs) > 0 {
		return fmt.Errorf("%s needs shared libraries %v (%v)", path, libs, err)
	}
	return nil
}

// build cross-compiles the agent into out.
func build(root, goarch, version, out string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -X main.version="+version, "-o", out, "./cmd/process-watcher")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build for linux/%s: %w", goarch, err)
	}
	return nil
}

// sourceDateEpoch returns the fixed modification time of the archive entries.
func sourceDateEpoch(flagValue int64, root string) (time.Time, error) {
	if flagValue > 0 {
		return time.Unix(flagValue, 0).UTC(), nil
	}
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH=%q is not a positive number of seconds", v)
		}
		return time.Unix(n, 0).UTC(), nil
	}
	cmd := exec.Command("git", "log", "-1", "--format=%ct")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return time.Time{}, errors.New("no modification time: set SOURCE_DATE_EPOCH or -source-date-epoch, or run inside a git checkout with a commit")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, fmt.Errorf("cannot read the commit time from %q", strings.TrimSpace(string(out)))
	}
	return time.Unix(n, 0).UTC(), nil
}

func run() error {
	version := flag.String("version", "", "release version, for example v0.1.0 (required)")
	out := flag.String("out", filepath.Join("dist", "release"), "output directory")
	archs := flag.String("arch", "", "comma separated architectures (default: all supported)")
	root := flag.String("root", ".", "repository root")
	config := flag.String("config", filepath.Join("examples", "process-watcher.full.yaml"), "configuration file shipped as process-watcher.yaml, relative to -root")
	license := flag.String("license", "LICENSE", "license file, relative to -root")
	packaging := flag.String("packaging", "packaging", "directory with install.sh, systemd/process-watcher.service and config/process-watcher.yaml, relative to -root")
	epoch := flag.Int64("source-date-epoch", 0, "modification time of the archive entries in seconds (default: SOURCE_DATE_EPOCH or the last commit)")
	flag.Parse()

	if err := checkVersion(*version); err != nil {
		return err
	}
	want := map[string]bool{}
	if *archs != "" {
		for _, a := range strings.Split(*archs, ",") {
			want[strings.TrimSpace(a)] = true
		}
	}
	var selected []target
	for _, t := range targets {
		if len(want) == 0 || want[t.goarch] {
			selected = append(selected, t)
			delete(want, t.goarch)
		}
	}
	if len(want) > 0 {
		return fmt.Errorf("unsupported architecture(s) %v: the eBPF collector supports linux/amd64 and linux/arm64 only", keys(want))
	}
	mtime, err := sourceDateEpoch(*epoch, *root)
	if err != nil {
		return err
	}
	files, err := loadPayload(*root, *config, *license, *packaging)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "pw-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	var sums []sum
	for _, t := range selected {
		bin := filepath.Join(tmp, "process-watcher-"+t.goarch)
		if err := build(*root, t.goarch, *version, bin); err != nil {
			return err
		}
		if err := checkStatic(bin, t.machine); err != nil {
			return err
		}
		data, err := os.ReadFile(bin)
		if err != nil {
			return err
		}
		written, err := writeArchives(*out, *version, t.goarch, files.entries(data), mtime)
		if err != nil {
			return err
		}
		for _, s := range written {
			fmt.Printf("%s  binary %d bytes (static, linux/%s)\n", s.name, len(data), t.goarch)
		}
		sums = append(sums, written...)
	}
	content, err := writeSums(*out, sums)
	if err != nil {
		return err
	}
	fmt.Print(content)
	return nil
}

func keys(m map[string]bool) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}
