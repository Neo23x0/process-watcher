package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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

// testPayload is a stand-in for the files of the repository.
func testPayload() payload {
	return payload{
		config:        []byte("config_version: 1\n"),
		license:       []byte("license text\n"),
		installer:     []byte("#!/bin/sh\necho install\n"),
		unit:          []byte("[Unit]\nDescription=test\n"),
		serviceConfig: []byte("config_version: 1\nwatch:\n  image_contains: [\"nginx\"]\n"),
		php: []entry{
			{"php/a.yaml", 0o644, []byte("a\n")},
			{"php/b.yaml", 0o644, []byte("b\n")},
		},
	}
}

// archiveFile is one entry of an unpacked archive.
type archiveFile struct {
	typ  byte
	mode int64
	data string
}

// readArchive unpacks a .tar.gz in memory, keyed by the entry name, and checks
// the metadata every entry must carry. order lists the names as they appear.
func readArchive(t *testing.T, file string, mtime time.Time) (files map[string]archiveFile, order []string) {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() || zr.Name != "" {
		t.Errorf("%s: gzip header carries a time or a name: %v %q", file, zr.ModTime, zr.Name)
	}
	files = map[string]archiveFile{}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Errorf("%s: owner %d/%d %q/%q, want root", h.Name, h.Uid, h.Gid, h.Uname, h.Gname)
		}
		if !h.ModTime.Equal(mtime) {
			t.Errorf("%s: mtime %v, want %v", h.Name, h.ModTime, mtime)
		}
		if _, dup := files[h.Name]; dup {
			t.Errorf("%s appears twice", h.Name)
		}
		files[h.Name] = archiveFile{h.Typeflag, h.Mode, string(data)}
		order = append(order, h.Name)
	}
	return files, order
}

func TestArchiveIsDeterministicAndComplete(t *testing.T) {
	entries := testPayload().entries([]byte("\x7fELF binary"))
	mtime := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.tar.gz"), filepath.Join(dir, "sub-b.tar.gz")
	const top = "process-watcher_v0.1.0_linux_amd64"
	if err := writeArchive(a, top, entries, mtime); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // a wall clock timestamp somewhere would show up now
	if err := writeArchive(b, top, entries, mtime); err != nil {
		t.Fatal(err)
	}
	ba, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if !bytes.Equal(ba, bb) {
		t.Fatal("the same input gave different archives")
	}

	files, order := readArchive(t, a, mtime)
	want := []string{
		"", "process-watcher", "process-watcher.yaml", "LICENSE",
		"packaging/", "packaging/install.sh",
		"packaging/systemd/", "packaging/systemd/process-watcher.service",
		"packaging/config/", "packaging/config/process-watcher.yaml",
		"php/", "php/a.yaml", "php/b.yaml",
	}
	for i := range want {
		want[i] = top + "/" + want[i]
	}
	if got := strings.Join(order, "\n"); got != strings.Join(want, "\n") {
		t.Errorf("archive entries:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	for name, f := range files {
		wantMode := int64(0o644)
		switch {
		case f.typ == tar.TypeDir:
			wantMode = 0o755
		case strings.HasSuffix(name, "/process-watcher"), strings.HasSuffix(name, "/install.sh"):
			wantMode = 0o755 // the two files that are run
		}
		if f.mode != wantMode {
			t.Errorf("%s: mode %o, want %o", name, f.mode, wantMode)
		}
		if (f.typ == tar.TypeDir) != strings.HasSuffix(name, "/") {
			t.Errorf("%s: type %q", name, f.typ)
		}
	}
	for _, e := range entries {
		if got := files[top+"/"+e.name].data; got != string(e.data) {
			t.Errorf("%s: content %q, want %q", e.name, got, e.data)
		}
	}
}

// Both names of an archive hold the same files; only the top directory differs,
// and the version appears in neither the unversioned name nor its directory.
func TestStableNameArchiveHasTheSameContent(t *testing.T) {
	entries := testPayload().entries([]byte("\x7fELF binary"))
	mtime := time.Unix(1_700_000_000, 0).UTC()
	out := t.TempDir()
	sums, err := writeArchives(out, "v1.2.3", "arm64", entries, mtime)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range sums {
		names = append(names, s.name)
	}
	if got, want := strings.Join(names, " "), "process-watcher_v1.2.3_linux_arm64.tar.gz process-watcher_linux_arm64.tar.gz"; got != want {
		t.Fatalf("archives %q, want %q", got, want)
	}

	strip := func(files map[string]archiveFile, top string) map[string]archiveFile {
		rel := map[string]archiveFile{}
		for name, f := range files {
			if !strings.HasPrefix(name, top+"/") {
				t.Errorf("entry %q is not below %q", name, top)
			}
			rel[strings.TrimPrefix(name, top+"/")] = f
		}
		return rel
	}
	pinned, _ := readArchive(t, filepath.Join(out, "process-watcher_v1.2.3_linux_arm64.tar.gz"), mtime)
	stable, _ := readArchive(t, filepath.Join(out, "process-watcher_linux_arm64.tar.gz"), mtime)
	a, b := strip(pinned, "process-watcher_v1.2.3_linux_arm64"), strip(stable, "process-watcher_linux_arm64")
	// The files, the top directory and four subdirectories (packaging/, packaging/systemd/, packaging/config/, php/).
	if want := len(entries) + 5; len(a) != want || len(b) != want {
		t.Fatalf("%d and %d entries, want %d", len(a), len(b), want)
	}
	for name, f := range a {
		if b[name] != f {
			t.Errorf("%s differs between the two archives", name)
		}
	}
	for name := range stable {
		if strings.Contains(name, "v1.2.3") {
			t.Errorf("%s: the unversioned archive carries the version", name)
		}
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

// SHA256SUMS lists every archive of the output directory, sorted by name, with
// the checksum of the file as it was written.
func TestSumsCoverEveryArchive(t *testing.T) {
	entries := testPayload().entries([]byte("\x7fELF binary"))
	mtime := time.Unix(1_700_000_000, 0).UTC()
	out := t.TempDir()
	var sums []sum
	for _, arch := range []string{"arm64", "amd64"} {
		s, err := writeArchives(out, "v1.2.3", arch, entries, mtime)
		if err != nil {
			t.Fatal(err)
		}
		sums = append(sums, s...)
	}
	content, err := writeSums(out, sums)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil || string(onDisk) != content {
		t.Fatalf("SHA256SUMS on disk differs from the returned content (%v)", err)
	}
	archives, _ := filepath.Glob(filepath.Join(out, "*.tar.gz"))
	if len(archives) != 4 {
		t.Fatalf("%d archives, want 4 (two architectures, two names each)", len(archives))
	}
	var listed []string
	for _, line := range strings.SplitAfter(content, "\n") {
		if line == "" {
			continue
		}
		hash, name, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "  ")
		if !ok {
			t.Fatalf("malformed line %q", line)
		}
		raw, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if h := sha256.Sum256(raw); hex.EncodeToString(h[:]) != hash {
			t.Errorf("%s: wrong checksum", name)
		}
		listed = append(listed, name)
	}
	if !sort.StringsAreSorted(listed) {
		t.Errorf("SHA256SUMS is not sorted by name: %v", listed)
	}
	var have []string
	for _, a := range archives {
		have = append(have, filepath.Base(a))
	}
	sort.Strings(have)
	if strings.Join(have, " ") != strings.Join(listed, " ") {
		t.Errorf("SHA256SUMS lists %v, the directory holds %v", listed, have)
	}
}

func TestLoadPayloadRejectsMissingAndEmptyFiles(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	load := func() (payload, error) {
		return loadPayload(root, "example.yaml", "LICENSE", "packaging", filepath.Join("examples", "php"))
	}
	if _, err := load(); err == nil {
		t.Fatal("an empty directory passed")
	}
	write("example.yaml", "config_version: 1\n")
	write("LICENSE", "license\n")
	write("packaging/install.sh", "#!/bin/sh\n")
	write("packaging/systemd/process-watcher.service", "[Unit]\n")
	write("packaging/config/process-watcher.yaml", "config_version: 1\n")
	if _, err := load(); err == nil || !strings.Contains(err.Error(), "examples") {
		t.Errorf("a missing PHP examples directory passed (%v)", err)
	}
	write("examples/php/README.md", "not a configuration\n")
	if _, err := load(); err == nil || !strings.Contains(err.Error(), "no *.yaml files") {
		t.Errorf("a PHP examples directory without *.yaml files passed (%v)", err)
	}
	write("examples/php/b.yaml", "config_version: 1\n")
	write("examples/php/a.yaml", "config_version: 1\n")
	p, err := load()
	if err != nil {
		t.Fatalf("a complete directory failed: %v", err)
	}
	if len(p.php) != 2 || p.php[0].name != "php/a.yaml" || p.php[1].name != "php/b.yaml" {
		t.Errorf("PHP examples %v, want php/a.yaml and php/b.yaml (the README.md is not shipped)", p.php)
	}
	write("packaging/systemd/process-watcher.service", "")
	if _, err := load(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an empty unit passed (%v)", err)
	}
	write("packaging/systemd/process-watcher.service", "[Unit]\n")
	write("packaging/install.sh", "echo no shebang\n")
	if _, err := load(); err == nil || !strings.Contains(err.Error(), "#!") {
		t.Errorf("an install script without a #! line passed (%v)", err)
	}
	if err := os.Remove(filepath.Join(root, "packaging", "config", "process-watcher.yaml")); err != nil {
		t.Fatal(err)
	}
	write("packaging/install.sh", "#!/bin/sh\n")
	if _, err := load(); err == nil {
		t.Error("a missing service configuration passed")
	}
}

// TestInstallerFindsEverythingInTheArchive checks the real files of the
// repository: install.sh reads its unit and configuration from paths next to
// itself ($HERE/...); every such path must exist in the archive layout.
func TestInstallerFindsEverythingInTheArchive(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	p, err := loadPayload(root, filepath.Join("examples", "process-watcher.full.yaml"), "LICENSE", "packaging", filepath.Join("examples", "php"))
	if err != nil {
		t.Fatal(err)
	}
	inArchive := map[string]bool{}
	for _, e := range p.entries([]byte("binary")) {
		inArchive[e.name] = true
	}
	refs := regexp.MustCompile(`"\$HERE/([^"]+)"`).FindAllStringSubmatch(string(p.installer), -1)
	if len(refs) == 0 {
		t.Fatal("install.sh references no file next to itself: the pattern or the script changed")
	}
	for _, m := range refs {
		if !inArchive["packaging/"+m[1]] {
			t.Errorf("install.sh reads $HERE/%s, which the archive does not hold at packaging/%s", m[1], m[1])
		}
	}
	// The installer and the unit agree on where the binary and the configuration go.
	for _, want := range []string{"/usr/local/bin/process-watcher", "/etc/process-watcher/config.yaml"} {
		if !strings.Contains(string(p.installer), want) || !strings.Contains(string(p.unit), want) {
			t.Errorf("install.sh and the unit do not both name %s", want)
		}
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n", filepath.Join(root, "packaging", "install.sh"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("sh -n install.sh: %v\n%s", err, out)
		}
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
