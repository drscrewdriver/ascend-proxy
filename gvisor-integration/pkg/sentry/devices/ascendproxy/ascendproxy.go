// Copyright 2026 The ascend-proxy Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Package ascendproxy implements proxying for the Ascend NPU Linux kernel
// driver (davinci_manager + hisi_hdc device files).
//
// This mirrors gVisor's nvproxy architecture. See:
//   - docs/gvisor-integration-analysis.md for design notes
//   - docs/ascend-ioctl-catalog.md for the ioctl whitelist data source
//
// Supported environment: CANN 9.1.0 + Ascend 910B2.
//
// Usage: register via ascendproxyRegisterDevices() called from
// runsc/boot/vfs.go, gated by the --ascendproxy flag.
package ascendproxy

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/devices/ascendproxy/ascendconf"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Options holds arguments to Register.
type Options struct {
	// CANNVersion is the target CANN toolkit version. Currently only 9.1.0
	// is validated; extend abis map for other versions.
	CANNVersion string

	// Caps is the bitmask of enabled capabilities. Set to CapAll for full
	// functionality; individual flags let callers restrict scope.
	Caps ascendconf.Caps

	// AllowUnsupported allows Register to proceed with a CANN version not
	// in the abis table. Use with caution.
	AllowUnsupported bool

	// HostDevManager is the host filesystem path to /dev/davinci_manager.
	// Default is the canonical path; override for tests or non-standard
	// driver installations.
	HostDevManager string

	// HostHdc is the host filesystem path to /dev/hisi_hdc.
	HostHdc string
}

// DeviceInfo describes the devices registered by this package. Returned by
// Register and stored on containerInfo for downstream code (e.g., seccomp
// filter installation).
type DeviceInfo struct {
	DavinciMajor uint32
	DavinciMinor uint32
	HdcMajor     uint32
	HdcMinor     uint32
}

// Kernel device numbers, per /proc/devices observation on 910B2.
//
//	504 davinci_manager
//	501 hisi_hdc
const (
	davinciManagerMajor uint32 = 504
	davinciManagerMinor uint32 = 0
	hdcMajor            uint32 = 501
	hdcMinor            uint32 = 0

	defaultDevManager = "/dev/davinci_manager"
	defaultHdc        = "/dev/hisi_hdc"
)

// abis maps supported CANN versions to their ioctl tables. Extend this when
// adding support for new CANN releases.
var abis = map[string]*abi{
	"9.1.0": abi910,
}

type abi struct {
	// ioctlMap holds all allowed ioctl commands for this CANN version.
	ioctlMap map[uint32]ioctlHandler
}

// Register installs davinci_manager and hisi_hdc as virtual character devices
// in vfsObj. Callers must invoke this before container processes attempt to
// open these paths; otherwise Sentry's VFS will return ENOENT.
func Register(vfsObj *vfs.VirtualFilesystem, opts *Options) (*DeviceInfo, error) {
	if opts == nil {
		return nil, fmt.Errorf("ascendproxy: nil Options")
	}

	// Version gate.
	entry, ok := abis[opts.CANNVersion]
	if !ok {
		if !opts.AllowUnsupported {
			return nil, fmt.Errorf("ascendproxy: unsupported CANN version %q", opts.CANNVersion)
		}
		// Fall through with the latest known ABI.
		entry = abi910
	}

	// Capability gate: at least one must be set.
	if opts.Caps == 0 {
		return nil, fmt.Errorf("ascendproxy: no capabilities selected")
	}

	devManager := opts.HostDevManager
	if devManager == "" {
		devManager = defaultDevManager
	}
	hdcPath := opts.HostHdc
	if hdcPath == "" {
		hdcPath = defaultHdc
	}

	// Register davinci_manager (a single well-known minor / no minors).
	if err := vfsObj.RegisterDevice(
		vfs.CharDevice,
		davinciManagerMajor,
		davinciManagerMinor,
		&davinciDevice{
			hostPath: devManager,
			abi:      entry,
			caps:     opts.Caps,
		},
		&vfs.RegisterDeviceOptions{
			Directory: "",
			PathName:  "davinci_manager",
		}); err != nil {
		return nil, fmt.Errorf("ascendproxy: registering davinci_manager: %w", err)
	}

	// Register hisi_hdc.
	if err := vfsObj.RegisterDevice(
		vfs.CharDevice,
		hdcMajor,
		hdcMinor,
		&hdcDevice{
			hostPath: hdcPath,
			abi:      entry,
			caps:     opts.Caps,
		},
		&vfs.RegisterDeviceOptions{
			Directory: "",
			PathName:  "hisi_hdc",
		}); err != nil {
		return nil, fmt.Errorf("ascendproxy: registering hisi_hdc: %w", err)
	}

	return &DeviceInfo{
		DavinciMajor: davinciManagerMajor,
		DavinciMinor: davinciManagerMinor,
		HdcMajor:     hdcMajor,
		HdcMinor:     hdcMinor,
	}, nil
}
