// Command release builds the release archives of process-watcher.
//
//	go run ./tools/release -version v0.1.0 [-out dist/release] [-arch amd64,arm64]
//
// For every architecture it cross-compiles the agent as a static Linux binary,
// checks that the result really is a single self-contained executable (no
// dynamic loader, no shared libraries) and writes
//
//	<out>/process-watcher_<version>_linux_<arch>.tar.gz
//
// with one directory of the same name holding: the binary process-watcher,
// the example configuration process-watcher.yaml (the agent finds a
// configuration next to its binary by itself), the LICENSE, and below php/
// every file of examples/php/ (the PHP deployment configurations of
// docs/php.md) so they are usable right after unpacking, without cloning the
// repository. A file <out>/SHA256SUMS lists the archives.
//
// Archive metadata is fixed (owner root, modification time from
// SOURCE_DATE_EPOCH or the time of the last commit, sorted entries, no gzip
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

// entry is one file of an archive; a name with slashes lies in a subdirectory
// (for example "php/php-fpm-dry-run.yaml").
type entry struct {
	name string
	mode int64
	data []byte
}

// writeArchive writes a deterministic .tar.gz: one top-level directory, a
// directory header right before the first entry of each subdirectory, the
// entries in the given order, owner root, the same modification time
// everywhere.
func writeArchive(path, dir string, entries []entry, mtime time.Time) error {
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
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// loadPHPExamples reads every *.yaml file directly below dir (not recursive),
// sorted by name, as archive entries below "php/". It requires at least one
// file, so an emptied or misspelled directory is a build error, not a
// silently thinner archive.
func loadPHPExamples(dir string) ([]entry, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no *.yaml files in %s", dir)
	}
	sort.Strings(matches)
	entries := make([]entry, 0, len(matches))
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{"php/" + filepath.Base(m), 0o644, data})
	}
	return entries, nil
}

// sumsLine formats one line of SHA256SUMS ("<hash>  <name>", as sha256sum -c reads it).
func sumsLine(name string, data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]) + "  " + name + "\n"
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
	phpExamples := flag.String("php-examples", filepath.Join("examples", "php"), "directory of PHP example configurations shipped below php/, relative to -root")
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
	cfg, err := os.ReadFile(filepath.Join(*root, *config))
	if err != nil {
		return err
	}
	lic, err := os.ReadFile(filepath.Join(*root, *license))
	if err != nil {
		return err
	}
	phpEntries, err := loadPHPExamples(filepath.Join(*root, *phpExamples))
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

	var sums []string
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
		dir := fmt.Sprintf("process-watcher_%s_linux_%s", *version, t.goarch)
		name := dir + ".tar.gz"
		archiveEntries := append([]entry{
			{"process-watcher", 0o755, data},
			{"process-watcher.yaml", 0o644, cfg},
			{"LICENSE", 0o644, lic},
		}, phpEntries...)
		err = writeArchive(filepath.Join(*out, name), dir, archiveEntries, mtime)
		if err != nil {
			return err
		}
		arc, err := os.ReadFile(filepath.Join(*out, name))
		if err != nil {
			return err
		}
		sums = append(sums, sumsLine(name, arc))
		fmt.Printf("%s  binary %d bytes (static, linux/%s), archive %d bytes\n", name, len(data), t.goarch, len(arc))
	}
	sort.Strings(sums)
	if err := os.WriteFile(filepath.Join(*out, "SHA256SUMS"), []byte(strings.Join(sums, "")), 0o644); err != nil {
		return err
	}
	fmt.Print(strings.Join(sums, ""))
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
