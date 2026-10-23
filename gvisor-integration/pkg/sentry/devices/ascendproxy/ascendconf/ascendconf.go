// Copyright 2026 The ascend-proxy Authors.
// Licensed under the Apache License, Version 2.0.

// Package ascendconf holds capability constants and configuration types for
// ascendproxy. Kept in a separate package so both the kernel-side
// implementation and the runsc-side flag parsing can import it without
// creating a circular dependency.
package ascendconf

// Caps is a bitmask of enabled functionality classes. Handlers declare which
// capabilities they require; a handler is dispatched only when all required
// bits are set on the device instance.
type Caps uint32

// Capability bits. Extend this list when adding new ioctls.
const (
	// CapInfer covers minimal inference path: device open + init handshake +
	// stream creation + kernel submission. Enabled by default.
	CapInfer Caps = 1 << 0

	// CapTrain adds training operations: backward pass + optimizer steps.
	// Includes 0x4d nr=0x2f and related training-time ioctls.
	CapTrain Caps = 1 << 1

	// CapMemory adds memory allocation and mapping (aclrtMalloc path).
	// Includes 0x4d nr=0x23 (memory map parameter, size 0x158).
	CapMemory Caps = 1 << 2

	// CapModel adds model loading + execution (aclmdl*).
	CapModel Caps = 1 << 3

	// CapHCCL adds multi-card collective communication. Requires 2+ cards;
	// currently ioctls in the 0x89 family remain untriggered even here.
	CapHCCL Caps = 1 << 4

	// CapDeviceQuery adds all safe query ioctls (0x57 config, 0x58 attribute
	// reads). Enabled by default.
	CapDeviceQuery Caps = 1 << 5

	// CapAll enables every capability, including HCCL.
	CapAll Caps = CapInfer | CapTrain | CapMemory | CapModel | CapHCCL | CapDeviceQuery

	// CapDefault is the recommended production config (single-card inference).
	CapDefault Caps = CapInfer | CapDeviceQuery
)
