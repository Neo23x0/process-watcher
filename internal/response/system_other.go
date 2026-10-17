//go:build !linux

package response

import (
	"errors"
	"syscall"
	"time"
)

type osSystem struct{}

// NewSystem returns a System that fails everything: the response feature only
// exists on Linux.
func NewSystem() System { return osSystem{} }

var errUnsupported = errors.New("only supported on Linux")

func (osSystem) PidfdOpen(int) (int, error)             { return -1, syscall.ENOSYS }
func (osSystem) PidfdSignal(int, syscall.Signal) error  { return syscall.ENOSYS }
func (osSystem) Close(int) error                        { return nil }
func (osSystem) ExeLink(int) (string, error)            { return "", syscall.ENOSYS }
func (osSystem) Cmdline(int, int) ([]byte, bool, error) { return nil, false, syscall.ENOSYS }
func (osSystem) BootNS() uint64                         { return 0 }
func (osSystem) Now() time.Time                         { return time.Now() }

// CheckSupport always fails off Linux.
func CheckSupport() error { return errUnsupported }
