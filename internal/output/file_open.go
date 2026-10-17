package output

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	fileMode = 0o600 // mode of log files, archives, the lock file and saved tails
	dirMode  = 0o700 // mode of newly created log directories

	tailChunk = 64 << 10 // buffer size for the torn-tail scan and copy
)

// Errors that callers may test with errors.Is.
var (
	// ErrLocked means another writer already owns the log path.
	ErrLocked = errors.New("log file is locked by another writer")
	// ErrSymlink means the log path (or its lock file) is a symbolic link.
	ErrSymlink = errors.New("log path is a symbolic link")
	// ErrNotRegular means the log path exists but is not a regular file.
	ErrNotRegular = errors.New("log path is not a regular file")
	// ErrClosed is returned by operations on a closed File.
	ErrClosed = errors.New("log file is closed")
)

// kindError carries a readable message and a sentinel for errors.Is.
type kindError struct {
	kind error
	msg  string
}

func (e *kindError) Error() string { return e.msg }
func (e *kindError) Unwrap() error { return e.kind }

// splitLogPath separates the directory and the final component without any
// lexical cleaning: the kernel resolves ".." and symlinks in the directory
// part, and only the final component is subject to the O_NOFOLLOW checks.
func splitLogPath(p string) (dir, base string, err error) {
	if p == "" {
		return "", "", errors.New("log file path is empty")
	}
	i := strings.LastIndexByte(p, '/')
	switch {
	case i < 0:
		dir, base = ".", p
	case i == 0:
		dir, base = "/", p[1:]
	default:
		dir, base = p[:i], p[i+1:]
	}
	if base == "" || base == "." || base == ".." {
		return "", "", fmt.Errorf("log file path %q does not name a file", p)
	}
	if strings.IndexByte(p, 0) >= 0 {
		return "", "", fmt.Errorf("log file path %q contains a NUL byte", p)
	}
	return dir, base, nil
}

// init acquires the directory handle, the lock and the active file, and
// repairs a torn last line. It leaves every opened descriptor in the File so
// the caller can release them on error.
func (f *File) init() error {
	var err error
	if f.dirFD, err = f.fs.OpenDir(f.dir); err != nil {
		return fmt.Errorf("open log directory %q: %w", f.dir, err)
	}
	if err := f.precheck(); err != nil {
		return err
	}
	if err := f.lock(); err != nil {
		return err
	}
	fd, fi, err := f.openLogFile(false)
	if err != nil {
		return err
	}
	f.fd = fd
	if fi.perm()&^fileMode != 0 {
		f.log.Warn("log file permissions are wider than 0600; leaving them unchanged",
			"path", f.opts.Path, "mode", fmt.Sprintf("%#o", fi.perm()))
	}
	info, size, err := f.repairTail(fd, fi.Size)
	if err != nil {
		return err
	}
	f.repair, f.size = info, size
	if info.Repaired {
		f.log.Warn("repaired a torn last line in the log file",
			"path", f.opts.Path, "bytes", info.Bytes, "saved_as", info.SavedAs)
	}
	return f.syncDir()
}

// precheck refuses obviously wrong targets before the lock file is created,
// so that e.g. a device node as log path does not get a lock file next to it.
// The authoritative checks happen on the opened descriptor.
func (f *File) precheck() error {
	fi, err := f.fs.StatNoFollowAt(f.dirFD, f.base)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil
	case err != nil:
		return fmt.Errorf("stat log file %q: %w", f.opts.Path, err)
	case fi.isSymlink():
		return f.symlinkError()
	case !fi.isRegular():
		return f.notRegularError(fi)
	}
	return nil
}

func (f *File) symlinkError() error {
	return &kindError{ErrSymlink, fmt.Sprintf(
		"refusing to use %q as log file: it is a symbolic link", f.opts.Path)}
}

func (f *File) notRegularError(fi fileInfo) error {
	return &kindError{ErrNotRegular, fmt.Sprintf(
		"refusing to use %q as log file: it is a %s, not a regular file", f.opts.Path, fi.typeName())}
}

// openLogFile opens the active file below the directory handle. O_NOFOLLOW
// refuses a symlink atomically; O_NONBLOCK keeps a FIFO from blocking the
// open and is cleared again once the file is known to be regular. With excl
// the file must not exist yet (rotation).
func (f *File) openLogFile(excl bool) (int, fileInfo, error) {
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_CREAT | unix.O_NOFOLLOW |
		unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	if excl {
		flags |= unix.O_EXCL
	}
	fd, err := f.fs.Openat(f.dirFD, f.base, flags, fileMode)
	if err != nil {
		switch {
		case errors.Is(err, unix.ELOOP):
			return -1, fileInfo{}, f.symlinkError()
		case errors.Is(err, unix.EISDIR):
			return -1, fileInfo{}, f.notRegularError(fileInfo{Mode: unix.S_IFDIR})
		}
		return -1, fileInfo{}, fmt.Errorf("open log file %q: %w", f.opts.Path, err)
	}
	fi, err := f.fs.Fstat(fd)
	if err != nil {
		_ = f.fs.Close(fd)
		return -1, fileInfo{}, fmt.Errorf("stat log file %q: %w", f.opts.Path, err)
	}
	if !fi.isRegular() {
		_ = f.fs.Close(fd)
		return -1, fileInfo{}, f.notRegularError(fi)
	}
	if err := f.fs.ClearNonblock(fd); err != nil {
		_ = f.fs.Close(fd)
		return -1, fileInfo{}, fmt.Errorf("configure log file %q: %w", f.opts.Path, err)
	}
	return fd, fi, nil
}

// lock takes the exclusive writer lock on "<path>.lock". The lock file is
// separate from the log so that it survives rotation, and it is never removed:
// unlinking it would let two writers lock two different inodes.
func (f *File) lock() error {
	lockName := f.base + ".lock"
	lockPath := f.opts.Path + ".lock"
	fd, err := f.fs.Openat(f.dirFD, lockName,
		unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, fileMode)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return &kindError{ErrSymlink, fmt.Sprintf("refusing to use lock file %q: it is a symbolic link", lockPath)}
		}
		return fmt.Errorf("open lock file %q: %w", lockPath, err)
	}
	fi, err := f.fs.Fstat(fd)
	if err != nil {
		_ = f.fs.Close(fd)
		return fmt.Errorf("stat lock file %q: %w", lockPath, err)
	}
	if !fi.isRegular() {
		_ = f.fs.Close(fd)
		return &kindError{ErrNotRegular, fmt.Sprintf("refusing to use lock file %q: it is a %s", lockPath, fi.typeName())}
	}
	if err := f.fs.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			holder := f.readLockHolder(fd)
			_ = f.fs.Close(fd)
			return &lockedError{path: f.opts.Path, lockPath: lockPath, pid: holder}
		}
		_ = f.fs.Close(fd)
		return fmt.Errorf("lock %q: %w", lockPath, err)
	}
	f.lockFD = fd
	// Record the owner for the diagnostics of a second writer. Purely
	// informational, so a failure here only deserves a warning.
	err = f.fs.Ftruncate(fd, 0)
	if err == nil {
		_, err = f.fs.Pwrite(fd, []byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	if err != nil {
		f.log.Warn("could not record pid in lock file", "path", lockPath, "error", err)
	}
	return nil
}

// readLockHolder returns the pid recorded in the lock file, or 0.
func (f *File) readLockHolder(fd int) int {
	var buf [32]byte
	n, err := f.fs.Pread(fd, buf[:], 0)
	if err != nil || n <= 0 {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

type lockedError struct {
	path, lockPath string
	pid            int
}

func (e *lockedError) Error() string {
	if e.pid > 0 {
		return fmt.Sprintf("log file %q is already in use by another process-watcher instance (pid %d, lock file %q)",
			e.path, e.pid, e.lockPath)
	}
	return fmt.Sprintf("log file %q is already in use by another process-watcher instance (lock file %q)",
		e.path, e.lockPath)
}

func (e *lockedError) Is(target error) bool { return target == ErrLocked }

// syncDir makes directory entry changes durable. Filesystems that cannot
// fsync a directory are tolerated.
func (f *File) syncDir() error {
	err := f.fs.SyncDir(f.dirFD)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOTSUP),
		errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOSYS):
		return nil
	}
	return fmt.Errorf("fsync log directory %q: %w", f.dir, err)
}

// repairTail makes sure the file ends with a newline. An incomplete last line
// (a torn write after a crash) is copied to "<path>.corrupt-<UTC timestamp>"
// and cut off; all complete lines stay untouched. It returns the repair
// report and the resulting file size.
func (f *File) repairTail(fd int, size int64) (RepairInfo, int64, error) {
	if size == 0 {
		return RepairInfo{}, 0, nil
	}
	var last [1]byte
	if err := f.preadFull(fd, last[:], size-1); err != nil {
		return RepairInfo{}, 0, fmt.Errorf("read tail of log file %q: %w", f.opts.Path, err)
	}
	if last[0] == '\n' {
		return RepairInfo{}, size, nil
	}
	keep, err := f.lastLineEnd(fd, size)
	if err != nil {
		return RepairInfo{}, 0, fmt.Errorf("scan log file %q for its last complete line: %w", f.opts.Path, err)
	}
	saved, err := f.saveTail(fd, keep, size)
	if err != nil {
		return RepairInfo{}, 0, fmt.Errorf("save the incomplete tail of log file %q: %w", f.opts.Path, err)
	}
	// Only cut the log once the tail is safely stored.
	if err := f.fs.Ftruncate(fd, keep); err != nil {
		return RepairInfo{}, 0, fmt.Errorf("truncate log file %q to its last complete line: %w", f.opts.Path, err)
	}
	if err := f.fs.Fsync(fd); err != nil {
		return RepairInfo{}, 0, fmt.Errorf("fsync log file %q after repair: %w", f.opts.Path, err)
	}
	return RepairInfo{Repaired: true, Bytes: size - keep, SavedAs: filepath.Join(f.dir, saved)}, keep, nil
}

// lastLineEnd returns the offset just after the last '\n' (0 if there is none).
func (f *File) lastLineEnd(fd int, size int64) (int64, error) {
	buf := make([]byte, tailChunk)
	for pos := size; pos > 0; {
		n := int64(len(buf))
		if pos < n {
			n = pos
		}
		chunk := buf[:n]
		if err := f.preadFull(fd, chunk, pos-n); err != nil {
			return 0, err
		}
		if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
			return pos - n + int64(i) + 1, nil
		}
		pos -= n
	}
	return 0, nil
}

// saveTail copies bytes [from, to) of fd into a new, uniquely named file
// below the log directory and returns its name.
func (f *File) saveTail(fd int, from, to int64) (string, error) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for attempt := 0; attempt < 1000; attempt++ {
		name := f.base + ".corrupt-" + stamp
		if attempt > 0 {
			name += "-" + strconv.Itoa(attempt)
		}
		cfd, err := f.fs.Openat(f.dirFD, name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := f.copyRange(fd, cfd, from, to); err != nil {
			_ = f.fs.Close(cfd)
			_ = f.fs.Unlinkat(f.dirFD, name)
			return "", err
		}
		if err := f.fs.Fsync(cfd); err != nil {
			_ = f.fs.Close(cfd)
			_ = f.fs.Unlinkat(f.dirFD, name)
			return "", err
		}
		if err := f.fs.Close(cfd); err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("no free name for the corrupt-tail file")
}

func (f *File) copyRange(src, dst int, from, to int64) error {
	buf := make([]byte, tailChunk)
	for off := from; off < to; {
		n := int64(len(buf))
		if to-off < n {
			n = to - off
		}
		chunk := buf[:n]
		if err := f.preadFull(src, chunk, off); err != nil {
			return err
		}
		for w := 0; w < len(chunk); {
			m, err := f.fs.Pwrite(dst, chunk[w:], off-from+int64(w))
			if err != nil {
				return err
			}
			if m <= 0 {
				return io.ErrShortWrite
			}
			w += m
		}
		off += n
	}
	return nil
}

// preadFull fills p from off; a short file is an error.
func (f *File) preadFull(fd int, p []byte, off int64) error {
	for len(p) > 0 {
		n, err := f.fs.Pread(fd, p, off)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		p = p[n:]
		off += int64(n)
	}
	return nil
}
