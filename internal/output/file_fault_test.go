package output

import (
	"sync"
	"testing"
)

// faultFS wraps the real filesystem calls and injects failures, so tests can
// provoke ENOSPC, EIO and friends deterministically.
type faultFS struct {
	realFS
	mu sync.Mutex

	writes, fsyncs int

	// writeErr makes Write fail after writeAllow bytes of the call reached the
	// file (a partial write). With writeOnce it fires only once.
	writeErr   error
	writeAllow int
	writeOnce  bool
	// shortWrite > 0 makes Write accept at most that many bytes per call
	// without an error.
	shortWrite int

	fsyncErr  error
	fsyncGate chan struct{} // if set, Fsync blocks until it is closed
	renameErr error
	pwriteErr error
	truncErr  error
	// openatErr is consulted before every Openat; a non-nil result is returned
	// instead of opening. beforeOpenat runs first (to race the path).
	openatErr    func(name string, flags int) error
	beforeOpenat func(name string, flags int)
}

var _ fsys = (*faultFS)(nil)

func (f *faultFS) with(fn func(f *faultFS)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *faultFS) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

func (f *faultFS) fsyncCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fsyncs
}

func (f *faultFS) Write(fd int, p []byte) (int, error) {
	f.mu.Lock()
	f.writes++
	werr, allow, short := f.writeErr, f.writeAllow, f.shortWrite
	if werr != nil && f.writeOnce {
		f.writeErr = nil
	}
	f.mu.Unlock()
	if werr != nil {
		n := min(allow, len(p))
		if n > 0 {
			if _, err := f.realFS.Write(fd, p[:n]); err != nil {
				return 0, err
			}
		}
		return n, werr
	}
	if short > 0 && len(p) > short {
		return f.realFS.Write(fd, p[:short])
	}
	return f.realFS.Write(fd, p)
}

func (f *faultFS) Fsync(fd int) error {
	f.mu.Lock()
	f.fsyncs++
	err, gate := f.fsyncErr, f.fsyncGate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if err != nil {
		return err
	}
	return f.realFS.Fsync(fd)
}

func (f *faultFS) Renameat(dirfd int, oldName, newName string) error {
	f.mu.Lock()
	err := f.renameErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.realFS.Renameat(dirfd, oldName, newName)
}

func (f *faultFS) Pwrite(fd int, p []byte, off int64) (int, error) {
	f.mu.Lock()
	err := f.pwriteErr
	f.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return f.realFS.Pwrite(fd, p, off)
}

func (f *faultFS) Ftruncate(fd int, size int64) error {
	f.mu.Lock()
	err := f.truncErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.realFS.Ftruncate(fd, size)
}

func (f *faultFS) Openat(dirfd int, name string, flags int, mode uint32) (int, error) {
	f.mu.Lock()
	hook, fail := f.beforeOpenat, f.openatErr
	f.mu.Unlock()
	if hook != nil {
		hook(name, flags)
	}
	if fail != nil {
		if err := fail(name, flags); err != nil {
			return -1, err
		}
	}
	return f.realFS.Openat(dirfd, name, flags, mode)
}

// openFaulty opens a File on top of a faultFS and closes it with the test.
func openFaulty(t *testing.T, opts FileOptions) (*File, *faultFS) {
	t.Helper()
	fs := &faultFS{}
	f, err := openFile(opts, fs)
	if err != nil {
		t.Fatalf("openFile: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, fs
}
