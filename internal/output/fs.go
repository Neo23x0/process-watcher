package output

import (
	"golang.org/x/sys/unix"
)

// fileInfo is the subset of fstat results the file output needs.
type fileInfo struct {
	Mode uint32 // st_mode including the file type bits
	Size int64
}

func (fi fileInfo) kind() uint32    { return fi.Mode & unix.S_IFMT }
func (fi fileInfo) isRegular() bool { return fi.kind() == unix.S_IFREG }
func (fi fileInfo) isSymlink() bool { return fi.kind() == unix.S_IFLNK }

// perm returns all permission bits including setuid, setgid and sticky.
func (fi fileInfo) perm() uint32 { return fi.Mode & 0o7777 }

// typeName describes the file type for error messages.
func (fi fileInfo) typeName() string {
	switch fi.kind() {
	case unix.S_IFDIR:
		return "directory"
	case unix.S_IFIFO:
		return "named pipe"
	case unix.S_IFSOCK:
		return "socket"
	case unix.S_IFCHR:
		return "character device"
	case unix.S_IFBLK:
		return "block device"
	case unix.S_IFLNK:
		return "symbolic link"
	case unix.S_IFREG:
		return "regular file"
	}
	return "special file"
}

// fsys is the narrow set of POSIX calls the file output is built on. All
// names are resolved relative to a directory file descriptor so that
// replacing a parent directory path cannot redirect later operations. The
// production implementation is realFS; tests wrap it to inject ENOSPC or EIO.
type fsys interface {
	OpenDir(path string) (int, error)
	Openat(dirfd int, name string, flags int, mode uint32) (int, error)
	Fstat(fd int) (fileInfo, error)
	StatNoFollowAt(dirfd int, name string) (fileInfo, error)
	Renameat(dirfd int, oldName, newName string) error
	Unlinkat(dirfd int, name string) error
	Pread(fd int, p []byte, off int64) (int, error)
	Pwrite(fd int, p []byte, off int64) (int, error)
	Write(fd int, p []byte) (int, error)
	Fsync(fd int) error
	SyncDir(fd int) error
	Ftruncate(fd int, size int64) error
	Flock(fd int, how int) error
	ClearNonblock(fd int) error
	Dup(fd int) (int, error)
	Close(fd int) error
}

// realFS implements fsys with golang.org/x/sys/unix; it builds on Linux and
// macOS alike.
type realFS struct{}

var _ fsys = realFS{}

// eintr repeats fn while it fails with EINTR.
func eintr(fn func() error) error {
	for {
		if err := fn(); err != unix.EINTR {
			return err
		}
	}
}

// eintrInt is eintr for calls that also return an int.
func eintrInt(fn func() (int, error)) (int, error) {
	for {
		n, err := fn()
		if err != unix.EINTR {
			return n, err
		}
	}
}

func (realFS) OpenDir(path string) (int, error) {
	return eintrInt(func() (int, error) {
		return unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	})
}

func (realFS) Openat(dirfd int, name string, flags int, mode uint32) (int, error) {
	return eintrInt(func() (int, error) { return unix.Openat(dirfd, name, flags, mode) })
}

func (realFS) Fstat(fd int) (fileInfo, error) {
	var st unix.Stat_t
	if err := eintr(func() error { return unix.Fstat(fd, &st) }); err != nil {
		return fileInfo{}, err
	}
	return fileInfo{Mode: uint32(st.Mode), Size: st.Size}, nil
}

func (realFS) StatNoFollowAt(dirfd int, name string) (fileInfo, error) {
	var st unix.Stat_t
	err := eintr(func() error { return unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) })
	if err != nil {
		return fileInfo{}, err
	}
	return fileInfo{Mode: uint32(st.Mode), Size: st.Size}, nil
}

func (realFS) Renameat(dirfd int, oldName, newName string) error {
	return eintr(func() error { return unix.Renameat(dirfd, oldName, dirfd, newName) })
}

func (realFS) Unlinkat(dirfd int, name string) error {
	return eintr(func() error { return unix.Unlinkat(dirfd, name, 0) })
}

func (realFS) Pread(fd int, p []byte, off int64) (int, error) {
	return eintrInt(func() (int, error) { return unix.Pread(fd, p, off) })
}

func (realFS) Pwrite(fd int, p []byte, off int64) (int, error) {
	return eintrInt(func() (int, error) { return unix.Pwrite(fd, p, off) })
}

func (realFS) Write(fd int, p []byte) (int, error) {
	return eintrInt(func() (int, error) { return unix.Write(fd, p) })
}

func (realFS) Fsync(fd int) error {
	return eintr(func() error { return unix.Fsync(fd) })
}

func (realFS) SyncDir(fd int) error {
	return eintr(func() error { return unix.Fsync(fd) })
}

func (realFS) Ftruncate(fd int, size int64) error {
	return eintr(func() error { return unix.Ftruncate(fd, size) })
}

func (realFS) Flock(fd int, how int) error {
	return eintr(func() error { return unix.Flock(fd, how) })
}

// ClearNonblock removes O_NONBLOCK, which is only set while opening so that
// a FIFO at the log path cannot block the open.
func (realFS) ClearNonblock(fd int) error {
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if fl&unix.O_NONBLOCK == 0 {
		return nil
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl&^unix.O_NONBLOCK)
	return err
}

// Dup duplicates fd (close-on-exec, never onto the stdio descriptors).
func (realFS) Dup(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
}

func (realFS) Close(fd int) error {
	if err := unix.Close(fd); err != nil && err != unix.EINTR {
		// After EINTR the descriptor is released on Linux and macOS; retrying
		// could close an unrelated, freshly reused descriptor.
		return err
	}
	return nil
}
