// Copyright 2026 The ascend-proxy Authors.
// Licensed under the Apache License, Version 2.0.

package ascendproxy

import (
	"gvisor.dev/gvisor/pkg/sentry/devices/ascendproxy/ascendconf"
)

// sig builds a full ioctl cmd from its parts. Uses Linux _IOC() layout.
//
//	dir: 0=NONE 1=WRITE 2=READ 3=RW
func sig(dir, magic, nr, size uint32) uint32 {
	return (dir << 30) | (size << 16) | (magic << 8) | nr
}

// abi910 is the ioctl table for CANN 9.1.0 / Ascend 910B2.
//
// Source: docs/ascend-ioctl-catalog.md (Phase 1 reverse engineering, 2026-10-24).
// 80 confirmed ALLOW entries. Deny-by-default handles the rest.
var abi910 = &abi{
	ioctlMap: map[uint32]ioctlHandler{
		// ===== Magic 0x45 — 初始化族 =====
		sig(0, 0x45, 0x00, 0):    {ascendconf.CapInfer, "设备探测"},
		sig(0, 0x45, 0x17, 0):    {ascendconf.CapInfer, "解锁 ioctl (时序第 9 位)"},

		// ===== Magic 0x4d NONE (8) =====
		sig(0, 0x4d, 0x03, 0):    {ascendconf.CapInfer, "设备初始化"},
		sig(0, 0x4d, 0x14, 0):    {ascendconf.CapInfer, "资源查询"},
		sig(0, 0x4d, 0x3a, 0):    {ascendconf.CapDeviceQuery, "设备属性查询"},
		sig(0, 0x4d, 0x3b, 0):    {ascendconf.CapDeviceQuery, "设备状态"},
		sig(0, 0x4d, 0x6c, 0):    {ascendconf.CapInfer, "设备同步"},
		sig(0, 0x4d, 0x70, 0):    {ascendconf.CapDeviceQuery, "设备能力查询"},
		sig(0, 0x4d, 0x9a, 0):    {ascendconf.CapInfer, "设备管理命令"},
		sig(0, 0x4d, 0xb6, 0):    {ascendconf.CapMemory, "资源释放"},

		// ===== Magic 0x4d WRITE size=0x158 (7) =====
		sig(1, 0x4d, 0x03, 0x158): {ascendconf.CapInfer, "设备初始化（带参数）"},
		sig(1, 0x4d, 0x0c, 0x158): {ascendconf.CapInfer, "LD 新发现 WRITE"},
		sig(1, 0x4d, 0x0d, 0x158): {ascendconf.CapInfer, "LD 新发现 WRITE"},
		sig(1, 0x4d, 0x24, 0x158): {ascendconf.CapInfer, "LD 新发现 WRITE"},
		sig(1, 0x4d, 0x2a, 0x158): {ascendconf.CapInfer, "LD 新发现 WRITE"},
		sig(1, 0x4d, 0x3d, 0x158): {ascendconf.CapInfer, "LD 新发现 WRITE"},
		sig(1, 0x4d, 0x40, 0x158): {ascendconf.CapInfer, "LD 新发现 WRITE"},

		// ===== Magic 0x4d RW size=0x158 (11) =====
		sig(3, 0x4d, 0x05, 0x158): {ascendconf.CapDeviceQuery, "设备信息查询"},
		sig(3, 0x4d, 0x0b, 0x158): {ascendconf.CapInfer, "上下文参数读写"},
		sig(3, 0x4d, 0x0f, 0x158): {ascendconf.CapDeviceQuery, "资源状态查询"},
		sig(3, 0x4d, 0x11, 0x158): {ascendconf.CapInfer, "配置参数读写"},
		sig(3, 0x4d, 0x1a, 0x158): {ascendconf.CapInfer, "流/事件参数"},
		sig(3, 0x4d, 0x23, 0x158): {ascendconf.CapMemory, "内存映射参数 (危险)"},
		sig(3, 0x4d, 0x27, 0x158): {ascendconf.CapInfer, "LD 新发现 RW"},
		sig(3, 0x4d, 0x2d, 0x158): {ascendconf.CapModel, "模型加载参数"},
		sig(3, 0x4d, 0x2e, 0x158): {ascendconf.CapModel, "推理执行参数"},
		sig(3, 0x4d, 0x31, 0x158): {ascendconf.CapDeviceQuery, "结果查询"},
		sig(3, 0x4d, 0x43, 0x158): {ascendconf.CapInfer, "未知 RW"},

		// ===== Magic 0x4d HCCL 双卡新增 (10) =====
		sig(0, 0x4d, 0x04, 0):    {ascendconf.CapHCCL, "多卡资源分配"},
		sig(0, 0x4d, 0x0e, 0):    {ascendconf.CapHCCL, "设备配对命令"},
		sig(0, 0x4d, 0x15, 0):    {ascendconf.CapHCCL, "多卡同步"},
		sig(0, 0x4d, 0x16, 0):    {ascendconf.CapHCCL, "多卡通信参数"},
		sig(0, 0x4d, 0x1b, 0):    {ascendconf.CapHCCL, "跨设备通信"},
		sig(0, 0x4d, 0x1c, 0):    {ascendconf.CapHCCL, "跨设备同步"},
		sig(0, 0x4d, 0x1d, 0):    {ascendconf.CapHCCL, "多卡链路查询"},
		sig(0, 0x4d, 0x20, 0):    {ascendconf.CapHCCL, "多卡状态查询"},
		sig(0, 0x4d, 0x6f, 0):    {ascendconf.CapHCCL, "多卡内存映射"},
		sig(0, 0x4d, 0x71, 0):    {ascendconf.CapHCCL, "设备间链路状态"},

		// ===== Magic 0x4d 训练新增 (1) =====
		sig(3, 0x4d, 0x2f, 0x158): {ascendconf.CapTrain, "反向传播/优化器"},

		// ===== Magic 0x55 设备能力族 (3) =====
		sig(2, 0x55, 0x00, 0x14): {ascendconf.CapInfer, "读设备能力（全局第一个 ioctl）"},
		sig(1, 0x55, 0x01, 0x04): {ascendconf.CapInfer, "设置设备模式"},
		sig(3, 0x55, 0x02, 0x10): {ascendconf.CapInfer, "设备能力读写"},

		// ===== Magic 0x57 配置查询族 (6) =====
		sig(3, 0x57, 0x01, 0x08): {ascendconf.CapDeviceQuery, "配置参数 01"},
		sig(3, 0x57, 0x04, 0x08): {ascendconf.CapDeviceQuery, "配置参数 04"},
		sig(3, 0x57, 0x07, 0x08): {ascendconf.CapDeviceQuery, "配置参数 07"},
		sig(3, 0x57, 0x08, 0x08): {ascendconf.CapDeviceQuery, "配置参数 08"},
		sig(3, 0x57, 0x09, 0x08): {ascendconf.CapDeviceQuery, "配置参数 09"},
		sig(3, 0x57, 0x0c, 0x08): {ascendconf.CapDeviceQuery, "配置参数 0c"},

		// ===== Magic 0x58 设备操作族 (15) =====
		sig(3, 0x58, 0x00, 0x1c):  {ascendconf.CapDeviceQuery, "设备属性查询"},
		sig(1, 0x58, 0x01, 0x1c):  {ascendconf.CapInfer, "设备属性设置"},
		sig(3, 0x58, 0x04, 0x1c):  {ascendconf.CapModel, "算子参数查询"},
		sig(3, 0x58, 0x05, 0x1c):  {ascendconf.CapInfer, "平台参数读写"},
		sig(3, 0x58, 0x06, 0x1c):  {ascendconf.CapModel, "算子参数查询"},
		sig(0, 0x58, 0x08, 0):     {ascendconf.CapHCCL, "多卡配置查询"},
		sig(1, 0x58, 0x0a, 0x1c):  {ascendconf.CapInfer, "属性设置"},
		sig(3, 0x58, 0x0b, 0x04):  {ascendconf.CapDeviceQuery, "开关量查询"},
		sig(3, 0x58, 0x0c, 0x08):  {ascendconf.CapDeviceQuery, "计数器查询"},
		sig(3, 0x58, 0x0d, 0x108): {ascendconf.CapMemory, "大数据块传输 (危险)"},
		sig(3, 0x58, 0x0f, 0x5c):  {ascendconf.CapInfer, "配置块读写"},
		sig(1, 0x58, 0x10, 0x34):  {ascendconf.CapInfer, "扩展写入"},
		sig(1, 0x58, 0x11, 0x34):  {ascendconf.CapInfer, "扩展写入"},
		sig(3, 0x58, 0x12, 0x34):  {ascendconf.CapInfer, "扩展读写"},
		sig(3, 0x58, 0x14, 0x48):  {ascendconf.CapInfer, "扩展读写"},

		// ===== Magic 0x5a 扩展命令族 (2) =====
		sig(0, 0x5a, 0x00, 0): {ascendconf.CapInfer, "扩展功能入口"},
		sig(0, 0x5a, 0x01, 0): {ascendconf.CapInfer, "扩展功能入口"},

		// ===== Magic 0x48 hisi_hdc 通道 (17) =====
		sig(0, 0x48, 0x07, 0): {ascendconf.CapInfer, "HDC 通道初始化"},
		sig(0, 0x48, 0x08, 0): {ascendconf.CapInfer, "HDC 通道配置"},
		sig(0, 0x48, 0x09, 0): {ascendconf.CapInfer, "HDC 命令"},
		sig(0, 0x48, 0x10, 0): {ascendconf.CapMemory, "HDC 数据传输准备"},
		sig(0, 0x48, 0x11, 0): {ascendconf.CapInfer, "HDC 命令"},
		sig(0, 0x48, 0x13, 0): {ascendconf.CapDeviceQuery, "HDC 状态查询"},
		sig(0, 0x48, 0x14, 0): {ascendconf.CapInfer, "HDC 命令"},
		sig(0, 0x48, 0x15, 0): {ascendconf.CapInfer, "HDC 命令"},
		sig(0, 0x48, 0x16, 0): {ascendconf.CapInfer, "HDC 命令"},
		sig(0, 0x48, 0x17, 0): {ascendconf.CapMemory, "HDC 数据传输"},
		sig(0, 0x48, 0x18, 0): {ascendconf.CapInfer, "HDC 完成确认"},
		sig(0, 0x48, 0x1a, 0): {ascendconf.CapInfer, "HDC 命令"},
		sig(0, 0x48, 0x1d, 0): {ascendconf.CapInfer, "HDC 通道关闭"},
		sig(0, 0x48, 0x40, 0): {ascendconf.CapInfer, "HDC 扩展"},
		sig(0, 0x48, 0x41, 0): {ascendconf.CapInfer, "HDC 扩展"},
		sig(0, 0x48, 0x42, 0): {ascendconf.CapInfer, "HDC 扩展"},
		sig(0, 0x48, 0x43, 0): {ascendconf.CapInfer, "HDC 扩展"},
	},
}
