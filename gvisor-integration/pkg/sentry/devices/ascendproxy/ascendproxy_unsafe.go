// Copyright 2026 The ascend-proxy Authors.
// Licensed under the Apache License, Version 2.0.

package ascendproxy

import "unsafe"

// unsafePointerImpl converts a Go slice's backing array pointer to uintptr
// for use in unix.RawSyscall. Isolated to an _unsafe.go file per gVisor
// convention so `unsafe` auditing is scoped.
func unsafePointerImpl(p *byte) uintptr {
	return uintptr(unsafe.Pointer(p))
}

// AT_FDCWD is the special dirfd for openat() relative to current working
// directory. Kept here to avoid importing golang.org/x/sys/unix at every
// call site.
const AT_FDCWD = -100
