package output

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	defaultSyncInterval = time.Second
	// maxStaleArchives bounds the cleanup of archives beyond KeepFiles.
	maxStaleArchives = 100000
)

// FileOptions configures the local log file.
type FileOptions struct {
	// Path of the active log file. Missing parent directories are created
	// with mode 0700; existing directories and files are never chmod'ed.
	Path string
	// RotateSizeBytes is the size limit of the active file. A line that would
	// push a non-empty file above it triggers a rotation first. 0 disables
	// rotation; negative values are invalid.
	RotateSizeBytes int64
	// KeepFiles is the number of closed archives (<path>.1 newest ...
	// <path>.<KeepFiles> oldest) kept next to the active file. It must be at
	// least 1 when rotation is enabled.
	KeepFiles int
	// SyncInterval is the maximum age of unsynced data; <= 0 means 1s.
	SyncInterval time.Duration
	// Logger receives operational diagnostics; nil discards them.
	Logger *slog.Logger
	// OnFatal is called at most once from the background sync goroutine when
	// fsync fails. It must not block indefinitely. Write errors are returned
	// to the caller of Write instead.
	OnFatal func(error)
}

// RepairInfo reports what happened to a torn last line when the file was
// opened.
type RepairInfo struct {
	Repaired bool   // an incomplete last line was found and cut off
	Bytes    int64  // size of the cut-off tail
	SavedAs  string // path of the file holding the tail ("<path>.corrupt-<UTC timestamp>")
}

// FileStats are counters of one File since it was opened.
type FileStats struct {
	Lines       int64 // lines written
	Bytes       int64 // bytes written
	Rotations   int64
	Syncs       int64 // successful fsync calls (periodic and Sync)
	WriteErrors int64 // failed Write calls
	SyncErrors  int64 // failed background fsync calls
	ActiveSize  int64 // current size of the active file
}

// File is the append-only local JSONL log: one exclusive writer per path, torn
// tail repair at open, size based rotation between complete lines and
// periodic fsync. It is safe for concurrent use.
type File struct {
	opts FileOptions
	fs   fsys
	log  *slog.Logger
	dir  string // directory part of Path, as given
	base string // final path component, relative to dirFD

	mu     sync.Mutex
	dirFD  int // directory all names are resolved against
	lockFD int // holds the flock for the whole lifetime
	fd     int // active file; -1 only after a failed rotation
	size   int64
	dirty  bool
	closed bool
	failed error // sticky: the file can no longer be trusted
	stats  FileStats
	repair RepairInfo

	closeErr  error
	closeDone chan struct{}
	stop      chan struct{}
	syncDone  chan struct{}
	syncOnce  sync.Once
}

// OpenFile opens (creating if needed) the log file, takes the writer lock,
// repairs a torn last line and starts the background fsync loop.
func OpenFile(opts FileOptions) (*File, error) {
	return openFile(opts, realFS{})
}

func openFile(opts FileOptions, fs fsys) (*File, error) {
	if opts.Path == "" {
		return nil, errors.New("output file: log file path is empty")
	}
	if opts.RotateSizeBytes < 0 {
		return nil, fmt.Errorf("output file: rotate size must not be negative (got %d)", opts.RotateSizeBytes)
	}
	if opts.RotateSizeBytes > 0 && opts.KeepFiles < 1 {
		return nil, fmt.Errorf("output file: keep_files must be at least 1 when rotation is enabled (got %d)", opts.KeepFiles)
	}
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = defaultSyncInterval
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	dir, base, err := splitLogPath(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("output file: %w", err)
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("output file: create log directory %q: %w", dir, err)
	}
	f := &File{
		opts: opts, fs: fs, log: opts.Logger, dir: dir, base: base,
		dirFD: -1, lockFD: -1, fd: -1,
		closeDone: make(chan struct{}),
		stop:      make(chan struct{}),
		syncDone:  make(chan struct{}),
	}
	if err := f.init(); err != nil {
		f.releaseFDs()
		return nil, err
	}
	go f.syncLoop()
	return f, nil
}

// Path returns the configured path of the active file.
func (f *File) Path() string { return f.opts.Path }

// Repair returns what the open-time torn-tail repair did.
func (f *File) Repair() RepairInfo { return f.repair }

// Stats returns a snapshot of the counters.
func (f *File) Stats() FileStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.stats
	s.ActiveSize = f.size
	return s
}

// Write appends one complete line (it must end in '\n') with a single write
// syscall, rotating first if the line would push the file above the limit.
// Any error is returned; after an error the line is not part of the file.
func (f *File) Write(line []byte) error {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return errors.New("output file: a log line must end with a newline")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrClosed
	}
	if f.failed != nil {
		return f.failed
	}
	if f.fd < 0 {
		// A previous rotation archived the file but could not create its
		// successor.
		if err := f.reopenLocked(); err != nil {
			f.stats.WriteErrors++
			return err
		}
	}
	if limit := f.opts.RotateSizeBytes; limit > 0 && f.size > 0 && f.size+int64(len(line)) > limit {
		if err := f.rotateLocked(); err != nil {
			f.stats.WriteErrors++
			return err
		}
	}
	n, err := f.writeLocked(line)
	if err != nil {
		f.stats.WriteErrors++
		return f.rollbackLocked(n, err)
	}
	f.size += int64(len(line))
	f.dirty = true
	f.stats.Lines++
	f.stats.Bytes += int64(len(line))
	return nil
}

// writeLocked writes line completely and returns the number of bytes that
// reached the file.
func (f *File) writeLocked(line []byte) (int, error) {
	written := 0
	for written < len(line) {
		n, err := f.fs.Write(f.fd, line[written:])
		if n > 0 {
			written += n
		}
		if err != nil {
			return written, err
		}
		if n <= 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// rollbackLocked restores the last good size after a failed write so that no
// partial line stays in the middle of the log.
func (f *File) rollbackLocked(written int, cause error) error {
	err := fmt.Errorf("write log file %q: %w", f.opts.Path, cause)
	if written == 0 {
		return err
	}
	f.dirty = true
	if terr := f.fs.Ftruncate(f.fd, f.size); terr != nil {
		// The partial line cannot be removed; refuse all further writes so no
		// line is ever appended behind it. The next start repairs the tail.
		f.failed = fmt.Errorf("%w (and the partial line could not be removed: %v)", err, terr)
		return f.failed
	}
	return err
}

func (f *File) archive(i int) string { return f.base + "." + strconv.Itoa(i) }

// rotateLocked archives the active file as <path>.1, shifting older archives
// up and dropping the oldest, and opens a fresh active file. Every step is a
// single atomic renameat below the directory handle and the writer lock stays
// held, so an interrupted rotation loses nothing and a retry heals gaps.
func (f *File) rotateLocked() error {
	if err := f.fs.Fsync(f.fd); err != nil {
		f.failed = fmt.Errorf("fsync log file %q before rotation: %w", f.opts.Path, err)
		return f.failed
	}
	k := f.opts.KeepFiles
	// top is the number of consecutive archives .1 ... .top (at most k-1, as
	// .k is replaced by .k-1 and thereby deleted).
	top := 0
	for top < k-1 {
		_, err := f.fs.StatNoFollowAt(f.dirFD, f.archive(top+1))
		if errors.Is(err, unix.ENOENT) {
			break
		}
		if err != nil {
			return fmt.Errorf("rotate log file %q: %w", f.opts.Path, err)
		}
		top++
	}
	for i := top; i >= 1; i-- {
		if err := f.fs.Renameat(f.dirFD, f.archive(i), f.archive(i+1)); err != nil {
			return fmt.Errorf("rotate log file %q: %w", f.opts.Path, err)
		}
	}
	if err := f.fs.Renameat(f.dirFD, f.base, f.archive(1)); err != nil {
		return fmt.Errorf("rotate log file %q: %w", f.opts.Path, err)
	}
	// The descriptor now refers to <path>.1, which was synced above.
	_ = f.fs.Close(f.fd)
	f.fd, f.size, f.dirty = -1, 0, false
	f.stats.Rotations++

	fd, _, err := f.openLogFile(true)
	if err != nil {
		return fmt.Errorf("create log file after rotation: %w", err)
	}
	f.fd = fd
	f.removeStaleArchives()
	if err := f.syncDir(); err != nil {
		return err
	}
	return nil
}

// removeStaleArchives deletes archives numbered above KeepFiles, left over
// from a configuration with a larger keep_files.
func (f *File) removeStaleArchives() {
	for i := f.opts.KeepFiles + 1; i <= f.opts.KeepFiles+maxStaleArchives; i++ {
		if err := f.fs.Unlinkat(f.dirFD, f.archive(i)); err != nil {
			if !errors.Is(err, unix.ENOENT) {
				f.log.Warn("could not remove stale log archive",
					"path", filepath.Join(f.dir, f.archive(i)), "error", err)
			}
			return
		}
	}
}

// reopenLocked recreates the active file after a failed rotation.
func (f *File) reopenLocked() error {
	fd, fi, err := f.openLogFile(false)
	if err != nil {
		return err
	}
	info, size, err := f.repairTail(fd, fi.Size)
	if err != nil {
		_ = f.fs.Close(fd)
		return err
	}
	if info.Repaired {
		f.log.Warn("repaired a torn last line in the log file",
			"path", f.opts.Path, "bytes", info.Bytes, "saved_as", info.SavedAs)
	}
	f.fd, f.size = fd, size
	return nil
}

// Sync flushes the active file to stable storage now.
func (f *File) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrClosed
	}
	if f.failed != nil {
		return f.failed
	}
	if f.fd < 0 {
		return nil
	}
	if err := f.fs.Fsync(f.fd); err != nil {
		f.stats.SyncErrors++
		f.failed = fmt.Errorf("fsync log file %q: %w", f.opts.Path, err)
		return f.failed
	}
	f.dirty = false
	f.stats.Syncs++
	return nil
}

// syncLoop fsyncs dirty data every SyncInterval. A failed fsync cannot be
// retried safely (the kernel may drop the error and the data), so it makes the
// file permanently failed and is reported through OnFatal.
func (f *File) syncLoop() {
	defer f.finishSync()
	t := time.NewTicker(f.opts.SyncInterval)
	defer t.Stop()
	for {
		select {
		case <-f.stop:
			return
		case <-t.C:
			if err := f.backgroundSync(); err != nil {
				// Release Close before calling out, in case OnFatal closes us.
				f.finishSync()
				if cb := f.opts.OnFatal; cb != nil {
					cb(err)
				}
				return
			}
		}
	}
}

func (f *File) finishSync() { f.syncOnce.Do(func() { close(f.syncDone) }) }

// backgroundSync syncs through a duplicate descriptor so that writers are not
// stalled behind a slow fsync; a concurrent rotation then still syncs the
// inode that is being archived.
func (f *File) backgroundSync() error {
	f.mu.Lock()
	if f.closed || f.failed != nil || !f.dirty || f.fd < 0 {
		f.mu.Unlock()
		return nil
	}
	dup, err := f.fs.Dup(f.fd)
	if err != nil {
		// Out of descriptors or similar: fall back to syncing under the lock.
		defer f.mu.Unlock()
		if err := f.fs.Fsync(f.fd); err != nil {
			return f.failSyncLocked(err)
		}
		f.dirty = false
		f.stats.Syncs++
		return nil
	}
	f.dirty = false
	f.mu.Unlock()

	err = f.fs.Fsync(dup)
	_ = f.fs.Close(dup)

	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		return f.failSyncLocked(err)
	}
	f.stats.Syncs++
	return nil
}

func (f *File) failSyncLocked(err error) error {
	f.stats.SyncErrors++
	if f.failed == nil {
		f.failed = fmt.Errorf("fsync log file %q: %w", f.opts.Path, err)
	}
	return f.failed
}

// Close stops the sync loop, fsyncs the file one last time and releases the
// descriptors and the writer lock. It is idempotent and returns the same
// result on every call.
func (f *File) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		<-f.closeDone
		return f.closeErr
	}
	f.closed = true
	close(f.stop)
	f.mu.Unlock()

	<-f.syncDone

	f.mu.Lock()
	defer f.mu.Unlock()
	defer close(f.closeDone)
	var errs []error
	if f.failed != nil {
		errs = append(errs, f.failed)
	}
	if f.fd >= 0 {
		if err := f.fs.Fsync(f.fd); err != nil {
			errs = append(errs, fmt.Errorf("fsync log file %q on close: %w", f.opts.Path, err))
		} else {
			f.stats.Syncs++
		}
	}
	if f.dirFD >= 0 {
		if err := f.syncDir(); err != nil {
			errs = append(errs, err)
		}
	}
	f.releaseFDsLocked(&errs)
	f.closeErr = errors.Join(errs...)
	return f.closeErr
}

// releaseFDs closes whatever is open; used when opening fails.
func (f *File) releaseFDs() {
	var ignored []error
	f.releaseFDsLocked(&ignored)
}

// releaseFDsLocked closes the log file first and the lock file last, so the
// lock is held until nothing else of ours is open.
func (f *File) releaseFDsLocked(errs *[]error) {
	for _, p := range []*int{&f.fd, &f.dirFD, &f.lockFD} {
		if *p < 0 {
			continue
		}
		if err := f.fs.Close(*p); err != nil {
			*errs = append(*errs, fmt.Errorf("close %q: %w", f.opts.Path, err))
		}
		*p = -1
	}
}
