package output

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testPaths(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	return dir, filepath.Join(dir, "events.jsonl")
}

// openLog opens a File that is closed with the test. The sync loop stays idle
// unless the test sets SyncInterval.
func openLog(t *testing.T, opts FileOptions) *File {
	t.Helper()
	if opts.SyncInterval == 0 {
		opts.SyncInterval = time.Hour
	}
	f, err := OpenFile(opts)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// testLine returns line i without newline, padded so that line plus newline
// is exactly size bytes.
func testLine(i, size int) string {
	s := fmt.Sprintf("L%07d|", i)
	if len(s) < size-1 {
		s += strings.Repeat("x", size-1-len(s))
	}
	return s
}

func writeTestLines(t *testing.T, f *File, from, to, size int) {
	t.Helper()
	for i := from; i < to; i++ {
		if err := f.Write([]byte(testLine(i, size) + "\n")); err != nil {
			t.Fatalf("Write line %d: %v", i, err)
		}
	}
}

// fileLines reads a log file and fails if it ends in a partial line.
func fileLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		return nil
	}
	if b[len(b)-1] != '\n' {
		t.Fatalf("%s ends with a partial line", path)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// archiveCount counts the consecutive archives path.1, path.2, ...
func archiveCount(path string) int {
	n := 0
	for {
		if _, err := os.Lstat(fmt.Sprintf("%s.%d", path, n+1)); err != nil {
			return n
		}
		n++
	}
}

// allLines returns the lines of all archives (oldest first) and the active file.
func allLines(t *testing.T, path string) []string {
	t.Helper()
	var lines []string
	for i := archiveCount(path); i >= 1; i-- {
		lines = append(lines, fileLines(t, fmt.Sprintf("%s.%d", path, i))...)
	}
	return append(lines, fileLines(t, path)...)
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestFileRotation(t *testing.T) {
	tests := []struct {
		name    string
		lines   int
		lineLen int // bytes per line including the newline
		rotate  int64
		keep    int
	}{
		{"single line", 1, 100, 4096, 3},
		{"exactly at the limit does not rotate", 10, 100, 1000, 3},
		{"one byte over the limit rotates", 11, 100, 1000, 3},
		{"many lines, all archives kept", 500, 100, 4096, 1000},
		{"many lines, oldest archives deleted", 2000, 100, 4096, 3},
		{"keep one archive", 300, 100, 1000, 1},
		{"every line larger than the limit", 5, 5000, 1024, 2},
		{"rotation disabled", 300, 100, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, path := testPaths(t)
			f := openLog(t, FileOptions{Path: path, RotateSizeBytes: tc.rotate, KeepFiles: tc.keep})
			writeTestLines(t, f, 0, tc.lines, tc.lineLen)
			if err := f.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			perFile := tc.lines
			if tc.rotate > 0 {
				perFile = max(1, int(tc.rotate)/tc.lineLen)
			}
			files := (tc.lines + perFile - 1) / perFile
			wantArchives := min(files-1, tc.keep)

			if got := archiveCount(path); got != wantArchives {
				t.Fatalf("archives = %d, want %d", got, wantArchives)
			}
			if _, err := os.Lstat(fmt.Sprintf("%s.%d", path, tc.keep+1)); err == nil {
				t.Errorf("archive beyond keep_files exists")
			}
			// What remains is a contiguous suffix of what was written.
			firstLine := (files - (wantArchives + 1)) * perFile
			var want []string
			for i := firstLine; i < tc.lines; i++ {
				want = append(want, testLine(i, tc.lineLen))
			}
			got := allLines(t, path)
			if len(got) != len(want) {
				t.Fatalf("surviving lines = %d, want %d", len(got), len(want))
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
				}
			}
			// Size limit holds unless a single line is larger than the limit.
			for _, p := range append([]string{path}, archiveNames(path, wantArchives)...) {
				st, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				if tc.rotate > 0 && st.Size() > tc.rotate && perFile != 1 {
					t.Errorf("%s is %d bytes, limit %d", p, st.Size(), tc.rotate)
				}
				if perm := st.Mode().Perm(); perm != 0o600 {
					t.Errorf("%s mode = %#o, want 0600", p, perm)
				}
			}
		})
	}
}

func archiveNames(path string, n int) []string {
	var names []string
	for i := 1; i <= n; i++ {
		names = append(names, fmt.Sprintf("%s.%d", path, i))
	}
	return names
}

func TestFileConcurrentWritesWithRotation(t *testing.T) {
	const writers, perWriter = 8, 250
	_, path := testPaths(t)
	f := openLog(t, FileOptions{Path: path, RotateSizeBytes: 8 << 10, KeepFiles: 1000})

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				line := fmt.Sprintf("w%d-%05d|%s\n", w, i, strings.Repeat("x", 60))
				if err := f.Write([]byte(line)); err != nil {
					t.Errorf("writer %d: %v", w, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if f.Stats().Rotations == 0 {
		t.Fatal("test did not rotate")
	}

	next := make([]int, writers)
	total := 0
	for _, line := range allLines(t, path) {
		var w, i int
		if _, err := fmt.Sscanf(line, "w%d-%d|", &w, &i); err != nil || len(line) != 69 {
			t.Fatalf("damaged line %q", line)
		}
		if i != next[w] {
			t.Fatalf("writer %d: got line %d, want %d (lost, duplicated or reordered)", w, i, next[w])
		}
		next[w]++
		total++
	}
	if total != writers*perWriter {
		t.Fatalf("lines = %d, want %d", total, writers*perWriter)
	}
}

func TestFileSecondWriterRefused(t *testing.T) {
	_, path := testPaths(t)
	opts := FileOptions{Path: path, RotateSizeBytes: 512, KeepFiles: 2, SyncInterval: time.Hour}
	f1 := openLog(t, opts)

	refused := func(when string) {
		t.Helper()
		f2, err := OpenFile(opts)
		if err == nil {
			f2.Close()
			t.Fatalf("%s: second writer was admitted", when)
		}
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("%s: error %v does not match ErrLocked", when, err)
		}
		for _, want := range []string{"already in use", fmt.Sprintf("pid %d", os.Getpid()), path + ".lock"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error %q lacks %q", when, err, want)
			}
		}
	}
	refused("before writing")
	writeTestLines(t, f1, 0, 100, 50)
	if f1.Stats().Rotations < 3 {
		t.Fatal("test did not rotate")
	}
	refused("after rotations") // the lock survives rotation

	if pid, err := os.ReadFile(path + ".lock"); err != nil || string(pid) != fmt.Sprintf("%d\n", os.Getpid()) {
		t.Errorf("lock file = %q, %v; want our pid", pid, err)
	}
	if err := f1.Close(); err != nil {
		t.Fatal(err)
	}
	f2, err := OpenFile(opts)
	if err != nil {
		t.Fatalf("open after the first writer closed: %v", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatal(err)
	}
}

// A different process holds the lock: the refusal names its pid, and the lock
// disappears with the holder even if it dies without a clean Close.
func TestFileLockAcrossProcesses(t *testing.T) {
	_, path := testPaths(t)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), holdLogEnv+"="+path)
	stdin, err := cmd.StdinPipe()
	must(t, err)
	stdout, err := cmd.StdoutPipe()
	must(t, err)
	must(t, cmd.Start())
	waited := false
	reap := func() {
		if !waited {
			waited = true
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(func() { _ = stdin.Close(); reap() })

	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper process: %q, %v", line, err)
	}
	_, err = OpenFile(FileOptions{Path: path})
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("error = %v, want ErrLocked", err)
	}
	if want := fmt.Sprintf("pid %d", cmd.Process.Pid); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name the holder (%s)", err, want)
	}

	reap() // the holder dies without closing anything
	f, err := OpenFile(FileOptions{Path: path, SyncInterval: time.Hour})
	if err != nil {
		t.Fatalf("lock not released by the dead holder: %v", err)
	}
	defer f.Close()
	if pid, err := os.ReadFile(path + ".lock"); err != nil || string(pid) != fmt.Sprintf("%d\n", os.Getpid()) {
		t.Errorf("lock file = %q, %v; want our pid after taking over", pid, err)
	}
}

func TestFileRefusedOpensLeakNoDescriptors(t *testing.T) {
	_, path := testPaths(t)
	opts := FileOptions{Path: path, SyncInterval: time.Hour}
	openLog(t, opts)
	// Count valid descriptors by probing; /dev/fd is not listable everywhere.
	count := func() int {
		n := 0
		for fd := 0; fd < 4096; fd++ {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
				n++
			}
		}
		return n
	}
	if _, err := OpenFile(opts); err == nil { // warm up
		t.Fatal("second writer admitted")
	}
	before := count()
	for i := 0; i < 50; i++ {
		if _, err := OpenFile(opts); !errors.Is(err, ErrLocked) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if after := count(); after != before {
		t.Fatalf("descriptors changed from %d to %d", before, after)
	}
}

func TestFileSymlinkAndSpecialFilesRefused(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir, path string)
		want  error
	}{
		{"symlink to a file", func(t *testing.T, dir, path string) {
			target := filepath.Join(dir, "target.log")
			must(t, os.WriteFile(target, []byte("precious\n"), 0o600))
			must(t, os.Symlink(target, path))
		}, ErrSymlink},
		{"dangling symlink", func(t *testing.T, dir, path string) {
			must(t, os.Symlink(filepath.Join(dir, "nowhere"), path))
		}, ErrSymlink},
		{"symlink to a directory", func(t *testing.T, dir, path string) {
			must(t, os.Symlink(dir, path))
		}, ErrSymlink},
		{"named pipe", func(t *testing.T, dir, path string) {
			must(t, unix.Mkfifo(path, 0o600))
		}, ErrNotRegular},
		{"directory", func(t *testing.T, dir, path string) {
			must(t, os.Mkdir(path, 0o700))
		}, ErrNotRegular},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := testPaths(t)
			tc.setup(t, dir, path)

			type result struct {
				f   *File
				err error
			}
			done := make(chan result, 1)
			go func() {
				f, err := OpenFile(FileOptions{Path: path, SyncInterval: time.Hour})
				done <- result{f, err}
			}()
			select {
			case r := <-done:
				if r.err == nil {
					r.f.Close()
					t.Fatal("opening succeeded")
				}
				if !errors.Is(r.err, tc.want) {
					t.Fatalf("error %q does not match %v", r.err, tc.want)
				}
				if tc.want == ErrSymlink && !strings.Contains(r.err.Error(), "symbolic link") {
					t.Errorf("error %q does not say why", r.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("OpenFile blocked")
			}
			if _, err := os.Lstat(path + ".lock"); err == nil {
				t.Error("a lock file was created next to a refused path")
			}
			if b, err := os.ReadFile(filepath.Join(dir, "target.log")); err == nil && string(b) != "precious\n" {
				t.Errorf("symlink target was modified: %q", b)
			}
		})
	}
}

// The path can be swapped for a symlink or FIFO after the early check but
// before the open; the open itself must refuse it.
func TestFileRefusesPathSwappedDuringOpen(t *testing.T) {
	tests := []struct {
		name string
		swap func(t *testing.T, dir, path string)
		want error
	}{
		{"symlink", func(t *testing.T, dir, path string) {
			target := filepath.Join(dir, "victim")
			must(t, os.WriteFile(target, []byte("secret\n"), 0o600))
			must(t, os.Symlink(target, path))
		}, ErrSymlink},
		{"named pipe", func(t *testing.T, dir, path string) {
			must(t, unix.Mkfifo(path, 0o600))
		}, ErrNotRegular},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := testPaths(t)
			fs := &faultFS{}
			fs.beforeOpenat = func(name string, flags int) {
				if name == "events.jsonl" {
					tc.swap(t, dir, path)
				}
			}
			done := make(chan error, 1)
			go func() {
				f, err := openFile(FileOptions{Path: path, SyncInterval: time.Hour}, fs)
				if err == nil {
					f.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, tc.want) {
					t.Fatalf("error = %v, want %v", err, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("OpenFile blocked")
			}
			if b, err := os.ReadFile(filepath.Join(dir, "victim")); err == nil && string(b) != "secret\n" {
				t.Errorf("victim file was modified: %q", b)
			}
			// The lock taken before the failed open must have been released.
			fs.with(func(f *faultFS) { f.beforeOpenat = nil })
			must(t, os.Remove(path))
			f, err := OpenFile(FileOptions{Path: path, SyncInterval: time.Hour})
			if err != nil {
				t.Fatalf("reopen after the refusal: %v", err)
			}
			f.Close()
		})
	}
}

func TestFileLockFileSymlinkRefused(t *testing.T) {
	dir, path := testPaths(t)
	target := filepath.Join(dir, "other")
	must(t, os.WriteFile(target, nil, 0o600))
	must(t, os.Symlink(target, path+".lock"))
	_, err := OpenFile(FileOptions{Path: path})
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("error = %v, want ErrSymlink", err)
	}
}

func TestFileTornTailRepair(t *testing.T) {
	long := strings.Repeat("0123456789\n", 20000) // spans several scan chunks
	tests := []struct {
		name     string
		content  string
		wantKept string
		wantTail string
	}{
		{"incomplete last line", "a\nb\npartial", "a\nb\n", "partial"},
		{"no newline at all", "partial", "", "partial"},
		{"newline terminated", "a\nb\n", "a\nb\n", ""},
		{"empty file", "", "", ""},
		{"only a newline", "\n", "\n", ""},
		{"tail spans several chunks", "a\nb\n" + strings.Repeat("z", 3*tailChunk+17), "a\nb\n", strings.Repeat("z", 3*tailChunk+17)},
		{"many complete lines then a torn one", long + `{"torn":`, long, `{"torn":`},
		{"binary tail", "ok\n\x00\x01\x02", "ok\n", "\x00\x01\x02"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := testPaths(t)
			if tc.content != "" {
				must(t, os.WriteFile(path, []byte(tc.content), 0o600))
			}
			f := openLog(t, FileOptions{Path: path})
			rep := f.Repair()

			if wantRepair := tc.wantTail != ""; rep.Repaired != wantRepair {
				t.Fatalf("Repaired = %v, want %v", rep.Repaired, wantRepair)
			}
			if got := mustRead(t, path); got != tc.wantKept {
				t.Fatalf("log after repair has %d bytes, want %d (complete lines must be kept)", len(got), len(tc.wantKept))
			}
			if tc.wantTail == "" {
				if rep.SavedAs != "" || rep.Bytes != 0 {
					t.Errorf("unexpected repair info %+v", rep)
				}
				if names, _ := filepath.Glob(path + ".corrupt-*"); len(names) != 0 {
					t.Errorf("corrupt files without a repair: %v", names)
				}
			} else {
				if rep.Bytes != int64(len(tc.wantTail)) {
					t.Errorf("Bytes = %d, want %d", rep.Bytes, len(tc.wantTail))
				}
				re := regexp.MustCompile(`^` + regexp.QuoteMeta(path) + `\.corrupt-\d{8}T\d{6}Z(-\d+)?$`)
				if !re.MatchString(rep.SavedAs) {
					t.Errorf("SavedAs = %q has an unexpected form", rep.SavedAs)
				}
				if got := mustRead(t, rep.SavedAs); got != tc.wantTail {
					t.Errorf("saved tail has %d bytes, want %d", len(got), len(tc.wantTail))
				}
				if perm := mode(t, rep.SavedAs); perm != 0o600 {
					t.Errorf("saved tail mode = %#o, want 0600", perm)
				}
				if filepath.Dir(rep.SavedAs) != dir {
					t.Errorf("saved tail is not next to the log: %s", rep.SavedAs)
				}
			}

			// The log continues cleanly behind the repaired content.
			must(t, f.Write([]byte("next\n")))
			must(t, f.Close())
			if got := mustRead(t, path); got != tc.wantKept+"next\n" {
				t.Fatalf("log after continuing is damaged")
			}
			f2 := openLog(t, FileOptions{Path: path})
			if f2.Repair().Repaired {
				t.Error("a clean log was repaired again")
			}
		})
	}
}

func TestFileTornTailRepairsDoNotCollide(t *testing.T) {
	_, path := testPaths(t)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		must(t, os.WriteFile(path, []byte(fmt.Sprintf("ok\ntorn%d", i)), 0o600))
		f, err := OpenFile(FileOptions{Path: path})
		must(t, err)
		saved := f.Repair().SavedAs
		must(t, f.Close())
		if saved == "" || seen[saved] {
			t.Fatalf("repair %d: SavedAs %q is empty or reused", i, saved)
		}
		seen[saved] = true
		if got := mustRead(t, saved); got != fmt.Sprintf("torn%d", i) {
			t.Fatalf("repair %d saved %q", i, got)
		}
	}
}

func TestFileTornTailRepairFailureKeepsEverything(t *testing.T) {
	tests := []struct {
		name         string
		inject       func(fs *faultFS)
		wantTailCopy bool // whether a (complete) corrupt file may remain
	}{
		{"saving the tail fails", func(fs *faultFS) { fs.pwriteErr = syscall.ENOSPC }, false},
		{"truncating the log fails", func(fs *faultFS) { fs.truncErr = syscall.EIO }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, path := testPaths(t)
			const content = "a\nb\npartial"
			must(t, os.WriteFile(path, []byte(content), 0o600))
			fs := &faultFS{}
			tc.inject(fs)
			f, err := openFile(FileOptions{Path: path, SyncInterval: time.Hour}, fs)
			if err == nil {
				f.Close()
				t.Fatal("open succeeded despite the injected failure")
			}
			if got := mustRead(t, path); got != content {
				t.Fatalf("log was modified: %q", got)
			}
			names, _ := filepath.Glob(path + ".corrupt-*")
			if !tc.wantTailCopy && len(names) != 0 {
				t.Errorf("incomplete tail copy left behind: %v", names)
			}
			// The failed open released its lock, and a healthy retry repairs.
			f2, err := OpenFile(FileOptions{Path: path, SyncInterval: time.Hour})
			if err != nil {
				t.Fatalf("retry: %v", err)
			}
			defer f2.Close()
			if !f2.Repair().Repaired || mustRead(t, path) != "a\nb\n" {
				t.Fatalf("retry did not repair: %+v", f2.Repair())
			}
		})
	}
}

func TestFilePermissionsAndDirectories(t *testing.T) {
	old := syscall.Umask(0) // so that the requested modes are what we observe
	defer syscall.Umask(old)

	t.Run("new files and directories", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "a", "b", "events.jsonl")
		f := openLog(t, FileOptions{Path: path, RotateSizeBytes: 200, KeepFiles: 2})
		writeTestLines(t, f, 0, 20, 50)
		must(t, f.Close())
		for _, d := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
			if perm := mode(t, d); perm != 0o700 {
				t.Errorf("directory %s mode = %#o, want 0700", d, perm)
			}
		}
		files := append([]string{path, path + ".lock"}, archiveNames(path, archiveCount(path))...)
		if len(files) < 4 {
			t.Fatal("test did not rotate")
		}
		for _, p := range files {
			if perm := mode(t, p); perm != 0o600 {
				t.Errorf("%s mode = %#o, want 0600", p, perm)
			}
		}
	})

	t.Run("existing directory and file are not chmod'ed", func(t *testing.T) {
		dir := t.TempDir()
		must(t, os.Chmod(dir, 0o755))
		path := filepath.Join(dir, "events.jsonl")
		must(t, os.WriteFile(path, []byte("old\n"), 0o644))
		must(t, os.Chmod(path, 0o644))

		logger, logs := captureLogger()
		f := openLog(t, FileOptions{Path: path, RotateSizeBytes: 100, KeepFiles: 1, Logger: logger})
		if n := strings.Count(logs.String(), "wider than 0600"); n != 1 {
			t.Errorf("permission warning logged %d times, want exactly once:\n%s", n, logs)
		}
		writeTestLines(t, f, 0, 10, 50) // rotates: the old file becomes the archive
		must(t, f.Close())

		if perm := mode(t, dir); perm != 0o755 {
			t.Errorf("existing directory mode = %#o, want it untouched (0755)", perm)
		}
		if perm := mode(t, path+".1"); perm != 0o600 && perm != 0o644 {
			t.Errorf("archive mode = %#o", perm)
		}
		if perm := mode(t, path); perm != 0o600 {
			t.Errorf("new active file mode = %#o, want 0600", perm)
		}
		if n := strings.Count(logs.String(), "wider than 0600"); n != 1 {
			t.Errorf("permission warning logged %d times in total, want once", n)
		}
	})

	t.Run("an existing file keeps its mode when appended to", func(t *testing.T) {
		_, path := testPaths(t)
		must(t, os.WriteFile(path, []byte("old\n"), 0o640))
		must(t, os.Chmod(path, 0o640))
		f := openLog(t, FileOptions{Path: path})
		must(t, f.Write([]byte("new\n")))
		must(t, f.Close())
		if perm := mode(t, path); perm != 0o640 {
			t.Errorf("mode = %#o, want 0640 (never widened or narrowed)", perm)
		}
	})
}

// The directory is opened once and every later operation goes through that
// handle, so moving the directory path cannot redirect rotation.
func TestFileRotationIgnoresSwappedDirectory(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	path := filepath.Join(logs, "events.jsonl")
	f := openLog(t, FileOptions{Path: path, RotateSizeBytes: 300, KeepFiles: 3})
	writeTestLines(t, f, 0, 2, 100)

	moved := filepath.Join(root, "moved")
	must(t, os.Rename(logs, moved))
	must(t, os.Mkdir(logs, 0o700)) // decoy at the original path
	writeTestLines(t, f, 2, 12, 100)
	must(t, f.Close())

	if entries, _ := os.ReadDir(logs); len(entries) != 0 {
		t.Fatalf("operations leaked into the swapped-in directory: %v", entries)
	}
	got := allLines(t, filepath.Join(moved, "events.jsonl"))
	if len(got) != 12 {
		t.Fatalf("lines in the original directory = %d, want 12", len(got))
	}
}

func TestFileRotationNormalizesArchives(t *testing.T) {
	t.Run("stale archives beyond keep_files are removed", func(t *testing.T) {
		_, path := testPaths(t)
		for i := 1; i <= 5; i++ {
			must(t, os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte(fmt.Sprintf("old%d\n", i)), 0o600))
		}
		f := openLog(t, FileOptions{Path: path, RotateSizeBytes: 100, KeepFiles: 2})
		writeTestLines(t, f, 0, 4, 60) // 60 + 60 > 100: rotates once per line after the first
		must(t, f.Close())
		if got := archiveCount(path); got != 2 {
			t.Fatalf("archives = %d, want 2", got)
		}
		if _, err := os.Lstat(path + ".3"); err == nil {
			t.Error("stale archive .3 survived")
		}
	})
	t.Run("a gap in the numbering is healed without loss", func(t *testing.T) {
		_, path := testPaths(t)
		must(t, os.WriteFile(path+".1", []byte("one\n"), 0o600))
		must(t, os.WriteFile(path+".3", []byte("three\n"), 0o600)) // .2 is missing
		must(t, os.WriteFile(path, []byte("active\n"), 0o600))
		f := openLog(t, FileOptions{Path: path, RotateSizeBytes: 10, KeepFiles: 5})
		must(t, f.Write([]byte("new\n")))
		must(t, f.Close())
		want := map[string]string{path + ".1": "active\n", path + ".2": "one\n", path + ".3": "three\n", path: "new\n"}
		for p, content := range want {
			if got := mustRead(t, p); got != content {
				t.Errorf("%s = %q, want %q", filepath.Base(p), got, content)
			}
		}
	})
}

func TestFileInjectedErrors(t *testing.T) {
	line := func(i int) []byte { return []byte(testLine(i, 40) + "\n") }

	t.Run("ENOSPC after a partial write truncates to the last good size", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, SyncInterval: time.Hour})
		must(t, f.Write(line(0)))
		fs.with(func(f *faultFS) { f.writeErr, f.writeAllow, f.writeOnce = syscall.ENOSPC, 17, true })

		err := f.Write(line(1))
		if !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("Write error = %v, want ENOSPC", err)
		}
		if got := mustRead(t, path); got != string(line(0)) {
			t.Fatalf("partial line left in the log: %q", got)
		}
		if f.Stats().WriteErrors != 1 {
			t.Errorf("WriteErrors = %d, want 1", f.Stats().WriteErrors)
		}
		// The condition is gone: writing works again and the log stays intact.
		must(t, f.Write(line(2)))
		if got := fileLines(t, path); len(got) != 2 || got[1] != testLine(2, 40) {
			t.Fatalf("log after recovery: %v", got)
		}
	})

	t.Run("a persistent error is returned on every write", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, SyncInterval: time.Hour})
		fs.with(func(f *faultFS) { f.writeErr = syscall.EIO })
		for i := 0; i < 3; i++ {
			if err := f.Write(line(i)); !errors.Is(err, syscall.EIO) {
				t.Fatalf("write %d: error = %v, want EIO", i, err)
			}
		}
		if got := mustRead(t, path); got != "" {
			t.Fatalf("log contains %q although every write failed", got)
		}
		if f.Stats().Lines != 0 || f.Stats().WriteErrors != 3 {
			t.Errorf("stats = %+v", f.Stats())
		}
	})

	t.Run("a partial line that cannot be removed disables the file", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, SyncInterval: time.Hour})
		must(t, f.Write(line(0)))
		fs.with(func(f *faultFS) {
			f.writeErr, f.writeAllow, f.writeOnce = syscall.ENOSPC, 11, true
			f.truncErr = syscall.EIO
		})
		err := f.Write(line(1))
		if !errors.Is(err, syscall.ENOSPC) || !strings.Contains(err.Error(), "could not be removed") {
			t.Fatalf("error = %v", err)
		}
		fs.with(func(f *faultFS) { f.truncErr = nil })
		if err := f.Write(line(2)); err == nil {
			t.Fatal("writing continued behind a partial line")
		}
		if err := f.Close(); err == nil {
			t.Error("Close hid the failure")
		}
		// The next start repairs the torn tail.
		f2 := openLog(t, FileOptions{Path: path})
		if !f2.Repair().Repaired {
			t.Error("torn tail not repaired at the next start")
		}
		if got := fileLines(t, path); len(got) != 1 || got[0] != testLine(0, 40) {
			t.Errorf("log after repair: %v", got)
		}
	})

	t.Run("short writes are completed", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, SyncInterval: time.Hour})
		fs.with(func(f *faultFS) { f.shortWrite = 7 })
		must(t, f.Write(line(0)))
		if got := mustRead(t, path); got != string(line(0)) {
			t.Fatalf("log = %q", got)
		}
		if n := fs.writeCount(); n < 6 {
			t.Errorf("only %d write calls for a 41 byte line at 7 bytes per call", n)
		}
	})

	t.Run("one write syscall per line", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, SyncInterval: time.Hour})
		for i := 0; i < 10; i++ {
			must(t, f.Write(line(i)))
		}
		if n := fs.writeCount(); n != 10 {
			t.Errorf("write calls = %d, want 10", n)
		}
	})

	t.Run("a failed rename during rotation loses nothing", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, RotateSizeBytes: 100, KeepFiles: 3, SyncInterval: time.Hour})
		must(t, f.Write(line(0)))
		must(t, f.Write(line(1)))
		fs.with(func(f *faultFS) { f.renameErr = syscall.EIO })
		if err := f.Write(line(2)); !errors.Is(err, syscall.EIO) { // would exceed 100 bytes
			t.Fatalf("error = %v, want EIO", err)
		}
		fs.with(func(f *faultFS) { f.renameErr = nil })
		must(t, f.Write(line(2)))
		must(t, f.Close())
		got := allLines(t, path)
		if len(got) != 3 || got[0] != testLine(0, 40) || got[1] != testLine(1, 40) || got[2] != testLine(2, 40) {
			t.Fatalf("lines after the failed rotation: %v", got)
		}
	})

	t.Run("failing to create the new file after rotation heals on the next write", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, RotateSizeBytes: 100, KeepFiles: 3, SyncInterval: time.Hour})
		must(t, f.Write(line(0)))
		must(t, f.Write(line(1)))
		fs.with(func(f *faultFS) {
			f.openatErr = func(name string, flags int) error {
				if name == "events.jsonl" {
					return syscall.EMFILE
				}
				return nil
			}
		})
		if err := f.Write(line(2)); !errors.Is(err, syscall.EMFILE) {
			t.Fatalf("error = %v, want EMFILE", err)
		}
		if f.Write(line(2)) == nil {
			t.Fatal("write succeeded without an active file")
		}
		fs.with(func(f *faultFS) { f.openatErr = nil })
		must(t, f.Write(line(2)))
		must(t, f.Close())
		got := allLines(t, path)
		if len(got) != 3 || got[2] != testLine(2, 40) {
			t.Fatalf("lines: %v", got)
		}
	})

	t.Run("fsync failure is reported through OnFatal and fails the file", func(t *testing.T) {
		_, path := testPaths(t)
		fatal := make(chan error, 4)
		fs := &faultFS{}
		f, err := openFile(FileOptions{Path: path, SyncInterval: 5 * time.Millisecond, OnFatal: func(err error) { fatal <- err }}, fs)
		must(t, err)
		t.Cleanup(func() { _ = f.Close() })

		fs.with(func(f *faultFS) { f.fsyncErr = syscall.EIO })
		must(t, f.Write(line(0)))
		select {
		case err := <-fatal:
			if !errors.Is(err, syscall.EIO) {
				t.Fatalf("OnFatal error = %v, want EIO", err)
			}
		case <-time.After(testWait):
			t.Fatal("OnFatal was not called")
		}
		time.Sleep(30 * time.Millisecond)
		if len(fatal) != 0 {
			t.Error("OnFatal called more than once")
		}
		if err := f.Write(line(1)); !errors.Is(err, syscall.EIO) {
			t.Errorf("Write after a failed fsync = %v, want the fsync error", err)
		}
		if err := f.Close(); !errors.Is(err, syscall.EIO) {
			t.Errorf("Close = %v, want the fsync error", err)
		}
		if f.Stats().SyncErrors == 0 {
			t.Error("SyncErrors not counted")
		}
	})

	t.Run("OnFatal may close the file", func(t *testing.T) {
		_, path := testPaths(t)
		closed := make(chan error, 1)
		fs := &faultFS{}
		var f *File
		var err error
		f, err = openFile(FileOptions{Path: path, SyncInterval: 5 * time.Millisecond,
			OnFatal: func(error) { closed <- f.Close() }}, fs)
		must(t, err)
		fs.with(func(f *faultFS) { f.fsyncErr = syscall.EIO })
		must(t, f.Write(line(0)))
		select {
		case <-closed:
		case <-time.After(testWait):
			t.Fatal("deadlock: OnFatal calling Close did not return")
		}
	})

	t.Run("writers are not stalled behind a slow fsync", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, SyncInterval: 5 * time.Millisecond})
		gate := make(chan struct{})
		var release sync.Once
		t.Cleanup(func() { release.Do(func() { close(gate) }) })
		fs.with(func(f *faultFS) { f.fsyncGate = gate })

		must(t, f.Write(line(0)))
		waitFor(t, "the background fsync to start and stall", func() bool { return fs.fsyncCount() >= 1 })
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 1; i <= 50; i++ {
				if err := f.Write(line(i)); err != nil {
					t.Errorf("Write %d: %v", i, err)
					return
				}
			}
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("writers blocked behind a stalled fsync")
		}
		release.Do(func() { close(gate) })
		must(t, f.Close())
		if got := fileLines(t, path); len(got) != 51 {
			t.Errorf("lines = %d, want 51", len(got))
		}
	})

	t.Run("Close syncs", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, SyncInterval: time.Hour})
		must(t, f.Write(line(0)))
		before := fs.fsyncCount()
		must(t, f.Close())
		if fs.fsyncCount() <= before {
			t.Fatal("Close did not fsync")
		}
		if f.Stats().Syncs == 0 {
			t.Error("Syncs not counted")
		}
	})

	t.Run("the sync loop syncs dirty data only", func(t *testing.T) {
		_, path := testPaths(t)
		f, fs := openFaulty(t, FileOptions{Path: path, SyncInterval: 5 * time.Millisecond})
		time.Sleep(40 * time.Millisecond)
		if n := fs.fsyncCount(); n != 0 {
			t.Fatalf("%d fsyncs without any write", n)
		}
		must(t, f.Write(line(0)))
		waitFor(t, "first background fsync", func() bool { return fs.fsyncCount() == 1 })
		time.Sleep(40 * time.Millisecond)
		if n := fs.fsyncCount(); n != 1 {
			t.Fatalf("fsyncs = %d after one write, want 1", n)
		}
		must(t, f.Write(line(1)))
		waitFor(t, "second background fsync", func() bool { return fs.fsyncCount() == 2 })
	})
}

func TestFileCloseAndWriteAfterClose(t *testing.T) {
	_, path := testPaths(t)
	f := openLog(t, FileOptions{Path: path})
	must(t, f.Write([]byte("a\n")))
	err1 := f.Close()
	err2 := f.Close()
	if err1 != nil || err2 != nil {
		t.Fatalf("Close = %v, %v", err1, err2)
	}
	if err := f.Write([]byte("b\n")); !errors.Is(err, ErrClosed) {
		t.Errorf("Write after Close = %v, want ErrClosed", err)
	}
	if err := f.Sync(); !errors.Is(err, ErrClosed) {
		t.Errorf("Sync after Close = %v, want ErrClosed", err)
	}
	// Concurrent Close calls all return after the shutdown completed.
	g := openLog(t, FileOptions{Path: path})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = g.Close() }()
	}
	wg.Wait()
}

func TestFileRejectsLinesWithoutNewline(t *testing.T) {
	_, path := testPaths(t)
	f := openLog(t, FileOptions{Path: path})
	for _, line := range [][]byte{nil, {}, []byte("no newline")} {
		if err := f.Write(line); err == nil {
			t.Errorf("Write(%q) succeeded", line)
		}
	}
	if got := mustRead(t, path); got != "" {
		t.Errorf("log = %q, want empty", got)
	}
}

func TestFileExplicitSyncAndStats(t *testing.T) {
	_, path := testPaths(t)
	f, fs := openFaulty(t, FileOptions{Path: path, RotateSizeBytes: 200, KeepFiles: 2, SyncInterval: time.Hour})
	writeTestLines(t, f, 0, 10, 50)
	before := fs.fsyncCount()
	must(t, f.Sync())
	if fs.fsyncCount() != before+1 {
		t.Error("Sync did not fsync")
	}
	st := f.Stats()
	if st.Lines != 10 || st.Bytes != 500 || st.Rotations == 0 || st.ActiveSize == 0 || st.ActiveSize > 200 {
		t.Errorf("stats = %+v", st)
	}
	if f.Path() != path {
		t.Errorf("Path = %q", f.Path())
	}
}

func TestFileOptionsValidation(t *testing.T) {
	dir, path := testPaths(t)
	must(t, os.WriteFile(filepath.Join(dir, "plainfile"), nil, 0o600))
	tests := []struct {
		name string
		opts FileOptions
	}{
		{"empty path", FileOptions{}},
		{"path without file name", FileOptions{Path: dir + "/"}},
		{"dot", FileOptions{Path: dir + "/."}},
		{"negative rotate size", FileOptions{Path: path, RotateSizeBytes: -1, KeepFiles: 1}},
		{"rotation without archives", FileOptions{Path: path, RotateSizeBytes: 100, KeepFiles: 0}},
		{"parent is a file", FileOptions{Path: filepath.Join(dir, "plainfile", "x.jsonl")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if f, err := OpenFile(tc.opts); err == nil {
				f.Close()
				t.Fatal("OpenFile succeeded")
			}
		})
	}
	// Relative paths are resolved against the working directory.
	t.Run("relative path", func(t *testing.T) {
		t.Chdir(dir)
		f, err := OpenFile(FileOptions{Path: "rel.jsonl", SyncInterval: time.Hour})
		must(t, err)
		must(t, f.Write([]byte("x\n")))
		must(t, f.Close())
		if got := mustRead(t, filepath.Join(dir, "rel.jsonl")); got != "x\n" {
			t.Errorf("content = %q", got)
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
