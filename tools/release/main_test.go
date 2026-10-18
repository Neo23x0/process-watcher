package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckVersion(t *testing.T) {
	for v, ok := range map[string]bool{
		"v0.1.0":         true,
		"v1.2.3":         true,
		"v10.20.30":      true,
		"v1.2.3-rc.1":    true,
		"v1.2.3-beta":    true,
		"":               false,
		"0.1.0":          false,
		"v1":             false,
		"v1.2":           false,
		"v01.2.3":        false,
		"v1.2.3-":        false,
		"v1.2.3+build":   false,
		"v1.2.3 ":        false,
		"v1.2.3/../x":    false,
		"v1.2.3;rm -rf":  false,
		"release-v1.2.3": false,
	} {
		if err := checkVersion(v); (err == nil) != ok {
			t.Errorf("checkVersion(%q) = %v, want ok=%v", v, err, ok)
		}
	}
}

func TestArchiveIsDeterministicAndComplete(t *testing.T) {
	entries := []entry{
		{"process-watcher", 0o755, []byte("\x7fELF binary")},
		{"process-watcher.yaml", 0o644, []byte("config_version: 1\n")},
		{"LICENSE", 0o644, []byte("license text\n")},
	}
	mtime := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.tar.gz"), filepath.Join(dir, "sub-b.tar.gz")
	if err := writeArchive(a, "process-watcher_v0.1.0_linux_amd64", entries, mtime); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // a wall clock timestamp somewhere would show up now
	if err := writeArchive(b, "process-watcher_v0.1.0_linux_amd64", entries, mtime); err != nil {
		t.Fatal(err)
	}
	ba, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if !bytes.Equal(ba, bb) {
		t.Fatal("the same input gave different archives")
	}

	zr, err := gzip.NewReader(bytes.NewReader(ba))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() || zr.Name != "" {
		t.Errorf("gzip header carries a time or a name: %v %q", zr.ModTime, zr.Name)
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Errorf("%s: owner %d/%d %q/%q, want root", h.Name, h.Uid, h.Gid, h.Uname, h.Gname)
		}
		if !h.ModTime.Equal(mtime) {
			t.Errorf("%s: mtime %v, want %v", h.Name, h.ModTime, mtime)
		}
		wantMode := int64(0o644)
		switch {
		case h.Typeflag == tar.TypeDir:
			wantMode = 0o755
		case strings.HasSuffix(h.Name, "/process-watcher"):
			wantMode = 0o755
		}
		if h.Mode != wantMode {
			t.Errorf("%s: mode %o, want %o", h.Name, h.Mode, wantMode)
		}
	}
	want := "process-watcher_v0.1.0_linux_amd64/ process-watcher_v0.1.0_linux_amd64/process-watcher " +
		"process-watcher_v0.1.0_linux_amd64/process-watcher.yaml process-watcher_v0.1.0_linux_amd64/LICENSE"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("archive entries:\n got %s\nwant %s", got, want)
	}
}

func TestWriteArchiveCreatesSubdirectoryHeaders(t *testing.T) {
	entries := []entry{
		{"process-watcher", 0o755, []byte("\x7fELF binary")},
		{"process-watcher.yaml", 0o644, []byte("config_version: 1\n")},
		{"LICENSE", 0o644, []byte("license text\n")},
		{"php/a.yaml", 0o644, []byte("a\n")},
		{"php/b.yaml", 0o644, []byte("b\n")},
	}
	mtime := time.Unix(1_700_000_000, 0).UTC()
	path := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := writeArchive(path, "pw_v0.1.0_linux_amd64", entries, mtime); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var names []string
	types := map[string]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		types[h.Name] = h.Typeflag
		if h.Typeflag == tar.TypeDir && h.Mode != 0o755 {
			t.Errorf("%s: directory mode %o, want 0755", h.Name, h.Mode)
		}
	}
	want := "pw_v0.1.0_linux_amd64/ pw_v0.1.0_linux_amd64/process-watcher " +
		"pw_v0.1.0_linux_amd64/process-watcher.yaml pw_v0.1.0_linux_amd64/LICENSE " +
		"pw_v0.1.0_linux_amd64/php/ pw_v0.1.0_linux_amd64/php/a.yaml pw_v0.1.0_linux_amd64/php/b.yaml"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("archive entries:\n got %s\nwant %s", got, want)
	}
	if types["pw_v0.1.0_linux_amd64/php/"] != tar.TypeDir {
		t.Error("php/ has no directory header")
	}
	// The subdirectory header is written exactly once even though two entries share it.
	n := 0
	for _, name := range names {
		if name == "pw_v0.1.0_linux_amd64/php/" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("php/ directory header written %d times, want 1", n)
	}
}

func TestLoadPHPExamples(t *testing.T) {
	entries, err := loadPHPExamples(filepath.Join("..", "..", "examples", "php"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 6 {
		t.Fatalf("expected the shipped PHP examples, found %d", len(entries))
	}
	prev := ""
	for _, e := range entries {
		if !strings.HasPrefix(e.name, "php/") || !strings.HasSuffix(e.name, ".yaml") {
			t.Errorf("entry name %q is not php/*.yaml", e.name)
		}
		if e.mode != 0o644 {
			t.Errorf("%s: mode %o, want 0644", e.name, e.mode)
		}
		if len(e.data) == 0 {
			t.Errorf("%s: empty", e.name)
		}
		if prev != "" && e.name <= prev {
			t.Errorf("entries not sorted: %q after %q", e.name, prev)
		}
		prev = e.name
	}
	if _, err := loadPHPExamples(filepath.Join(t.TempDir(), "no-such-dir")); err == nil {
		t.Error("a missing directory passed")
	}
	empty := t.TempDir()
	if _, err := loadPHPExamples(empty); err == nil {
		t.Error("a directory without *.yaml files passed")
	}
}

func TestSumsLineIsWhatSha256sumReads(t *testing.T) {
	// echo -n abc | sha256sum
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  x.tar.gz\n"
	if got := sumsLine("x.tar.gz", []byte("abc")); got != want {
		t.Errorf("sumsLine = %q, want %q", got, want)
	}
}

func TestCheckStaticRejectsWhatIsNotASingleStaticExecutable(t *testing.T) {
	if err := checkStatic(filepath.Join(t.TempDir(), "missing"), elf.EM_X86_64); err == nil {
		t.Error("a missing file passed")
	}
	notELF := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkStatic(notELF, elf.EM_X86_64); err == nil {
		t.Error("a shell script passed")
	}
}

// TestBuiltAgentsAreStaticSingleBinaries builds the real agent for both
// architectures and applies the check the release applies.
func TestBuiltAgentsAreStaticSingleBinaries(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the agent twice")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool in PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range targets {
		t.Run(tg.goarch, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "process-watcher")
			if err := build(root, tg.goarch, "v0.0.0-test", bin); err != nil {
				t.Fatal(err)
			}
			if err := checkStatic(bin, tg.machine); err != nil {
				t.Fatal(err)
			}
			// The other architecture's machine type must be refused.
			other := elf.EM_X86_64
			if tg.machine == elf.EM_X86_64 {
				other = elf.EM_AARCH64
			}
			if err := checkStatic(bin, other); err == nil {
				t.Error("a binary for the wrong machine passed")
			}
		})
	}
}
