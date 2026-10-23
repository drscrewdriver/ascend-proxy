// Copyright 2026 The ascend-proxy Authors.
// Licensed under the Apache License, Version 2.0.

package ascendproxy

import (
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Filters returns seccomp-bpf rules limiting which ioctls Sentry can execute
// against the real /dev/davinci_manager and /dev/hisi_hdc file descriptors.
//
// This is the "second line of defense": even if the container process somehow
// bypasses davinciFD.Ioctl (e.g., a Sentry bug lets it escape), Sentry itself
// is prevented from issuing arbitrary ioctls on the host devices it holds.
//
// The rule set is derived from abi.ioctlMap keys; see gen_filters.go.
//
// This mirrors nvproxy's frontendIoctlFilters() pattern.
func Filters() seccomp.SyscallRules {
	rules := seccomp.Or{}
	for cmd := range abi910.ioctlMap {
		rules = append(rules, seccomp.EqualTo(uintptr(cmd)))
	}
	// Sentry's ioctl(cmd) arg 1 is the cmd; arg 0 is fd (any), arg 2 is
	// pointer (any), args 3-5 unused. We constrain arg 1 only.
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		ioctlSyscall: seccomp.PerArg{
			seccomp.NonNegativeFD{},
			rules,
			seccomp.AnyValue{},
		},
	})
}

// ioctlSyscall is the syscall number for ioctl on the target architecture.
// Populated per-build via linker flags or by arch-specific file.
var ioctlSyscall uintptr = 29 // aarch64 __NR_ioctl; x86_64 uses 16
