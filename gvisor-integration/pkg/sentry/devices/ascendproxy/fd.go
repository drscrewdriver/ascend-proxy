// Copyright 2026 The ascend-proxy Authors.
// Licensed under the Apache License, Version 2.0.

package ascendproxy

import (
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/devices/ascendproxy/ascendconf"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// davinciFD is the file description returned by davinciDevice.Open for
// /dev/davinci_manager. It implements Ioctl filtering against the ABI table.
//
// +stateify savable
type davinciFD struct {
	// abi and caps are immutable after creation.
	abi  *abi
	caps ascendconf.Caps

	// hostFD is the real /dev/davinci_manager file descriptor that Sentry
	// holds. All allowed ioctls are executed against it via RawSyscall.
	hostFD int32

	// mu protects the mutable fields below.
	mu mutex `state:"wait"`

	// q is the wait queue for poll/select.
	q waiter.EventQueue `state:"zeroinitialize"`

	// pinnedResources tracks memory allocations made via 0x4d RW ioctls of
	// size 0x158. Not yet populated; reserved for Phase 4b implementation.
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *davinciFD) Release(ctx context.Context) {
	if err := unix.Close(int(fd.hostFD)); err != nil {
		ctx.Warningf("ascendproxy: close hostFD failed: %v", err)
	}
	fd.hostFD = -1
}

// EventRegister implements vfs.FileDescriptionImpl.EventRegister.
func (fd *davinciFD) EventRegister(e *waiter.Entry) {
	fd.mu.Lock()
	fd.q = append(fd.q, e)
	fd.mu.Unlock()
}

// EventUnregister implements vfs.FileDescriptionImpl.EventUnregister.
func (fd *davinciFD) EventUnregister(e *waiter.Entry) {
	fd.mu.Lock()
	for i, w := range fd.q {
		if w == e {
			fd.q = append(fd.q[:i], fd.q[i+1:]...)
			break
		}
	}
	fd.mu.Unlock()
}

// Readiness implements vfs.FileDescriptionImpl.Readiness.
//
// davinci_manager is a character device without poll-able state (all access
// is ioctl-based). Always ready for write, never for read.
func (fd *davinciFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return mask & waiter.EventOut
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
//
// The dispatcher:
//  1. Extracts the ioctl nr from cmd.
//  2. Looks up the handler in abi.ioctlMap; on miss returns EPERM
//     (deny-by-default).
//  3. Verifies the handler's capability is enabled on this instance.
//  4. Copies parameter struct from application memory (via
//     usermem.IO.CopyIn).
//  5. Executes real ioctl via unix.RawSyscall on fd.hostFD.
//  6. Copies result struct back (if handler declared it mutable).
func (fd *davinciFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	size := linux.IOC_SIZE(cmd)
	dir := linux.IOC_DIR(cmd)
	argPtr := hostarch.Addr(args[2].Pointer())

	// Look up by full cmd (32-bit: dir + size + magic + nr). Ascend uses
	// 8 different magics (0x45/0x48/0x4d/0x55/0x57/0x58/0x5a/0x89), so keying
	// by nr alone would conflate across families.
	h, ok := fd.abi.ioctlMap[cmd]
	if !ok {
		return 0, linuxerr.EPERM
	}
	// Capability gate.
	if h.capSet != 0 && (h.capSet & fd.caps) == 0 {
		ctx.Debugf("ascendproxy: ioctl cmd=0x%08x requires caps %v, have %v",
			cmd, h.capSet, fd.caps)
		return 0, linuxerr.EPERM
	}

	// Allocate parameter buffer on Go heap (safe for GC).
	var buf []byte
	if size > 0 {
		buf = make([]byte, size)

		// CopyIn when the ioctl reads from application memory.
		if dir&linux.IOC_WRITE != 0 {
			if _, err := uio.CopyIn(ctx, nil, argPtr, safemem.FromSliceWriter(buf), usermem.CopyFlags(0)); err != nil {
				return 0, err
			}
		}
	}

	// Execute the real ioctl. RawSyscall is fine — no preemption concerns
	// here since we hold no Go locks across the call.
	var ptr uintptr
	if size > 0 {
		ptr = uintptr(unsafePointer(&buf[0]))
	}
	// Note: Sentry's own seccomp filter (see seccomp_filter.go) restricts
	// which ioctl numbers we can pass here; disallowed ones return EPERM
	// at the kernel level, not SIGSYS.
	ret, _, errno := unix.RawSyscall(unix.SYS_IOCTL,
		uintptr(fd.hostFD),
		uintptr(cmd),
		ptr)
	runtime.KeepAlive(fd)
	runtime.KeepAlive(buf)

	// CopyOut when the ioctl writes to application memory.
	if errno == 0 && size > 0 && dir&linux.IOC_READ != 0 {
		if _, err := uio.CopyOut(ctx, nil, argPtr, safemem.FromSliceReader(buf), usermem.CopyFlags(0)); err != nil {
			return 0, err
		}
	}

	if errno != 0 {
		return 0, errno.ToLinuxError()
	}
	return uintptr(ret), nil
}

// ioctlHandler describes how a specific ioctl number should be dispatched.
type ioctlHandler struct {
	// capSet is the required capability bits (0 = always allowed).
	capSet ascendconf.Caps
	// desc is a short human-readable description (for logging).
	desc string
}

// unsafePointer is a thin wrapper to avoid importing unsafe in this file.
// Real implementation lives in ascendproxy_unsafe.go.
func unsafePointer(p *byte) uintptr { return unsafePointerImpl(p) }
