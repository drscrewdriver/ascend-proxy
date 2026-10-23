# gVisor 集成分析（Phase 4a 交付物）

> 目标：把阶段二完成的 C 独立代理集成进 gVisor，实现"昇腾版 nvproxy"
>
> **状态**：骨架（阶段三期间填充）

---

## 1. 参考对照：nvproxy 三层架构

### 1.1 gVisor nvproxy 分层

```
┌─────────────────────────────────────────────────┐
│ Layer 1: Sentry (Go 用户态内核)                  │
│   - 拦截所有 syscall (systrap/ptrace/kvm)        │
│   - VFS + fd table                              │
│   - 分发到具体 device handler                    │
└─────────────────┬───────────────────────────────┘
                  │ 函数调用
                  ▼
┌─────────────────────────────────────────────────┐
│ Layer 2: nvproxy Go module (Sentry 内部)         │
│   - pkg/sentry/devices/nvproxy/                  │
│   - 每个 ioctl 号 → 一个 Go handler              │
│   - 部分纯用户态模拟，部分转发到 frontend        │
└─────────────────┬───────────────────────────────┘
                  │ unix socket + memfd
                  ▼
┌─────────────────────────────────────────────────┐
│ Layer 3: nvproxy frontend (C 特权进程)           │
│   - pkg/sentry/devices/nvproxy/frontend/         │
│   - 打开真 /dev/nvidiaX                          │
│   - 执行真 ioctl，结果回传                       │
└─────────────────────────────────────────────────┘
```

### 1.2 ascend-proxy 对应映射

| nvproxy 层 | ascend-proxy 对应 | 状态 |
|-----------|------------------|------|
| Layer 1 Sentry | gVisor 已有，复用 | ✅ 现成 |
| Layer 2 nvproxy Go | **需要新写** `ascendproxy` Go 模块 | ❌ 待建 |
| Layer 3 frontend | 阶段二的 proxy_main.c **改造** | ⚠️ 协议需适配 |

**关键洞察**：我们的 `inject_seccomp.c` 在集成后**会被丢弃**（Sentry 已经拦下 ioctl，不再需要 seccomp）。`whitelist.c` 逻辑迁移到 Go。`proxy_main.c` 变成 frontend 角色。

---

## 2. Sentry device 注册机制（阶段三调研）

> 基于 gVisor master 分支源码阅读（本地 `~/dev/gvisor`，2026-10-24）

### 2.1 nvproxy 文件布局（实际 7593 行 Go，20 个文件）

| 文件 | 行数 | 作用 |
|------|------|------|
| `nvproxy.go` | 333 | 总入口 + `Register(vfsObj, opts)` 设备注册 |
| `handlers.go` | 156 | ioctl handler 定义 + 能力掩码 |
| `object.go` | 428 | 设备 fd 对象（实现 vfs.FileOperations） |
| `frontend.go` + `frontend_unsafe.go` | ~1170 | host frontend 子进程 + 真 ioctl 转发 |
| `seccomp_filters.go` | 161 | 对 frontend 自己限制的 seccomp 规则 |
| `version.go` | 1533 | NVIDIA 驱动版本 → ABI 映射表 |
| `uvm.go` + `uvm_*.go` | ~800 | UVM (Unified Virtual Memory) 子系统 |

### 2.2 关键发现 1：双向 seccomp 隔离

`seccomp_filters.go` 显示 gVisor **不只限制容器，还限制 frontend 自己**：

```go
func frontendIoctlFilters(enabledCaps nvconf.DriverCaps) []seccomp.SyscallRule {
    var ioctlRules []seccomp.SyscallRule
    for _, feIoctl := range []struct{ ... }{
        // 逐个枚举允许 frontend 执行的 ioctl 编号
    }
    // 拼成 syscall.Rule，仅允许 ioctl syscall + 精确命中的编号
}
```

**启示**：ascend-proxy 集成时应该双白名单：
- Sentry 侧（容器能发什么 ioctl）
- Frontend 侧（能代执行什么） — 避免 Sentry 自身被攻击后滥用特权

### 2.3 关键发现 2：capability 能力掩码

`handlers.go`：

```go
type frontendIoctlHandler struct {
    handler func(*frontendIoctlState) (uintptr, error)
    capSet  nvconf.DriverCaps    // 位掩码
}

func feHandler(h func(*frontendIoctlState) (uintptr, error),
               caps nvconf.DriverCaps) frontendIoctlHandler {
    return frontendIoctlHandler{h, caps}
}
```

**启示**：我们的白名单应扩展为 `(magic, nr, capability)` 三元组。不同部署场景（推理/训练/多卡）可开关不同能力，与阶段一发现的 HCCL 边界自然对应。

### 2.4 关键发现 3：ABI 版本绑定

`nvproxy.go:Register` 入口：

```go
abiEntry, ok := abis[opts.DriverVersion]
if !ok {
    return nil, fmt.Errorf("unsupported Nvidia driver version: %s", opts.DriverVersion)
}
```

**启示**：ascendproxy 需绑 CANN 版本。当前实测环境：CANN 9.1.0 + 910B2 + driver 25.2.1，`version.go` 先写单一入口。

### 2.5 深入阅读：frontendFD.Ioctl 实现（frontend.go:213）

实际代码发现 nvproxy **不存在独立 frontend 进程**（与早期 gVisor 文档不同），当前实现是：

```go
// frontend.go:213 — Sentry 内部直接执行
func (fd *frontendFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr,
                            args arch.SyscallArguments) (uintptr, error) {
    cmd := args[1].Uint()
    nr := linux.IOC_NR(cmd)
    // …
    result, err := fd.dev.nvp.abi.frontendIoctl[nr].handle(&fi)
}

// frontend_unsafe.go:41 — 实际调用真 ioctl
func frontendIoctlInvokeNoStatus(...) {
    n, _, errno := unix.RawSyscall(
        unix.SYS_IOCTL,
        uintptr(fi.fd.hostFD),              // ← Sentry 持有的真 host fd
        frontendIoctlCmd(fi.nr, fi.ioctlParamsSize),
        uintptr(unsafe.Pointer(ioctlParams)))
}
```

**含义**：Sentry 自己持有 /dev/nvidia* 的 host fd，直接 RawSyscall。安全性靠：
1. Sentry 自己的 **seccomp filter**（限制 Sentry 能向 host 发哪些 ioctl）
2. Sentry 内部的 **ABI 分发表**（`abi.frontendIoctl[nr]`）

### 2.6 深入阅读：参数传递模式（frontendIoctlSimple）

```go
func frontendIoctlSimple[Params any, PtrParams hasStatusPtr[Params]](
    fi *frontendIoctlState) (uintptr, error) {
    var ioctlParamsValue Params
    ioctlParams := PtrParams(&ioctlParamsValue)
    if int(fi.ioctlParamsSize) != ioctlParams.SizeBytes() { return 0, linuxerr.EINVAL }
    ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr)    // 容器内存 → Go 结构体
    n, err := frontendIoctlInvoke(fi, ioctlParams)  // 真 ioctl
    ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr)   // Go 结构体 → 容器内存
    return n, nil
}
```

使用 **Go 泛型 + marshal 接口**，每个参数类型只需声明 `CopyIn/CopyOut`，handler 代码不到 15 行。

**启示**：ascendproxy 中我们需为 6 个常见 size（0 / 4 / 8 / 0x14 / 0x1c / 0x34 / 0x5c / 0x108 / 0x158）定义对应结构体。无结构体时退化为 opaque blob。与阶段二 `process_vm_readv/writev` 同语义，但 Sentry 内部无跨进程开销。

### 2.7 runsc CLI 层集成链路（阶段 C）

```
runsc --nvproxy          ┐
                          │  runsc/config/config.go 定义 flag
OCI spec annotation       │  runsc/specutils/nvidia.go:NVProxyEnabled()
  ↓                        │
boot.NewSentry()         │  runsc/boot/loader.go
  ↓                        │
nvproxy.Register(vfs, opts)   ← 入口！我们写 ascendproxy.Register 同位
  ↓                        │
创建 frontendDevice{minor}, 注册到 virtualFilesystem
  ↓                        │
容器 open("/dev/nvidia0") → Sentry VFS 匹配到 frontendDevice →
返回 frontendFD，后续 ioctl 自动分发到 frontendFD.Ioctl
```

关键 API：`vfs.VirtualFilesystem.RegisterDeviceAtPath("/dev/davinci_manager", &davinciDevice{})`

### 2.8 待调研项（下一步）

- [ ] `object.go` 中的 `deviceFile` 实现与 `nvproxy.object` 关系（尚不确定需不需要 object tracking）
- [ ] `save_restore.go` 序列化机制（影响 checkpoint/restore）
- [ ] `pkg/abi/nvgpu/` 里的结构体定义风格（需为昇腾写 `pkg/abi/davinci/`）
- [ ] `pkg/sentry/devices/BUILD` 自动发现机制

---

## 3. ascendproxy Go 模块设计（阶段 4b 起点）

### 3.1 目录结构

```
pkg/sentry/devices/ascendproxy/
├── ascendproxy.go     — 设备注册 + 顶层 ioctl dispatcher
├── davinci.go         — /dev/davinci* 伪设备实现
├── hdc.go             — /dev/hisi_hdc 伪设备实现
├── whitelist.go       — 80 ALLOW + 24 DENY（从 catalog 生成）
├── params.go          — 结构体 marshal（可选，Phase 4b 后期）
├── frontend.go        — 与 host frontend 通信
└── ascendproxy_test.go
```

### 3.2 接口草图

```go
// davinci.go — 伪设备实现
package ascendproxy

import "gvisor.dev/gvisor/pkg/sync"

type davinciFD struct {
    pDevice *davinciDevice
    realFd  int32  // 通过 frontend 打开后返回的句柄 id
    mu      sync.Mutex
}

func (d *davinciFD) Ioctl(ctx *_syscall.Context, cmd uint64, arg uint64) int64 {
    action := whitelistLookup(cmd)
    switch action {
    case PROXY_ALLOW:
        return d.forwardIoctl(ctx, cmd, arg)
    case PROXY_DENY:
        return -_errno.EPERM
    }
    return -_errno.ENOTTY
}
```

### 3.3 白名单代码生成

```go
// whitelist.go — 由 tools/gen_whitelist.go 从 catalog.md 自动生成
package ascendproxy

var whitelistMap = map[uint64]Action{
    // 0x45 NONE nr=0x17 — 解锁 ioctl（时序第 9 位）
    0x00004517: PROXY_ALLOW,

    // 0x4d NONE nr=0x03 — 设备初始化
    0x00004d03: PROXY_ALLOW,

    // ... 80 条 ALLOW
    // ... 24 条 DENY
}
```

工具脚本：`tools/gen_whitelist.go`，读取 `docs/ascend-ioctl-catalog.md` 表格生成 Go 源码。

---

## 4. Frontend 协议适配（阶段 4b 关键改动）

### 4.1 nvproxy 现有协议

nvproxy 用**匿名共享内存 (memfd)** + **ioctl on listener fd** 传递：
- Sentry → frontend：ioctl cmd + memfd 中的参数结构体
- frontend → Sentry：执行结果 + 修改后的 memfd

### 4.2 阶段二 proxy_main.c 现状

当前使用 `process_vm_readv/writev` 跨进程读写容器内存，无 memfd。

### 4.3 需要的改造

| 项 | 现状 | 目标 | 工作量 |
|----|------|------|-------|
| 消息格式 | seccomp NOTIF | 自定义 socket 协议 | 中 |
| 内存传递 | process_vm_* | memfd + mmap | 中 |
| 会话管理 | 一 listener fd 一会话 | Sentry 进程级 socket | 低 |
| 设备 fd 归属 | supervisor 打开 | frontend 打开 | 无改动 |

**评估**：改造 ~200 行 C 代码，约 3-5 天。

---

## 5. 集成测试矩阵（阶段 4b 尾期）

| 测试类型 | 场景 | 预期 |
|---------|------|------|
| 单元 | whitelist_map 覆盖率 | 104 条全命中 |
| 集成 | runsc 启动 → 容器内 open("/dev/davinci_manager") | fd 有效，Sentry 日志见注册事件 |
| 端到端 | torch.npu.is_available() | True，proxy 日志见 ~10 条 ioctl |
| 端到端 | x.mm(y) 推理 | 结果与直通一致 |
| 安全 | 容器内 open("/dev/davinci_manager") via ptrace bypass | 拒绝（Sentry 强制） |
| 安全 | 未列入白名单的 ioctl 编号 | ENOTTY |
| 性能 | 单次 ioctl 延迟 | Sentry→frontend→Sentry < 200μs |
| 性能 | 训练吞吐 | 相比直通 <10% 下降 |

---

## 6. 上游贡献路径（阶段 4c）

- [ ] 阅读 gVisor CONTRIBUTING.md
- [ ] 在 gvisor.dev mailing list 发 RFC 帖子（标题：`[RFC] Ascend NPU device support`）
- [ ] 收集社区反馈决定是否提 PR
- [ ] 若社区欢迎 → 走 CLA + 完整 review 流程

**注意**：gVisor 上游只支持 NVIDIA GPU 的 nvproxy，是否有兴趣接昇腾是未知数。即使不合并，fork 版本 + 完整文档本身也是可交付物。

---

## 7. 风险清单

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| gVisor 不支持 aarch64 | 中 | 高 | 提前确认；nvproxy 主要在 x86_64；昇腾是 aarch64 |
| Sentry ioctl 语义与 Linux 差异导致 torch_npu 崩溃 | 中 | 高 | 阶段三先做兼容性验证 |
| nvproxy frontend 协议未文档化 | 低 | 中 | 直接读源码 |
| 上游拒绝合并 | 高 | 低 | 作为学习项目独立发布 |

---

## 8. 决策要点

| 决策 | 选择 | 理由 |
|------|------|------|
| 是否保留 C 独立代理分支？ | **保留** | 有独立价值：能塞进 Kata/其他沙箱，或作为轻量方案 |
| Go 模块自己写还是 port nvproxy 代码？ | **自己写** | nvproxy 是 NVIDIA 特定 ioctl 语义，不能直接 port |
| 白名单来源 | catalog.md + 生成脚本 | 保持数据单一真源 |
| frontend 协议 | 参考 nvproxy 但简化 | 不必完全对齐 |

---

## 9. 更新日志

- 2026-10-24 骨架创建（阶段二完成后）
- 2026-10-24 阶段三 W6 完成：gVisor 源码获取 + nvproxy 精读 A+C
  * `~/dev/gvisor` 88MB 就位（codeload tar.gz）
  * Bazel 8.8.1 安装（ghproxy 镜像）
  * nvproxy 发现：不存在独立 frontend 进程，Sentry 直接 RawSyscall
  * frontendIoctlSimple 使用 Go 泛型 + marshal 接口
  * runsc CLI 链路：flag → NVProxyEnabled → Register(vfs)
  * **构建卡住**：bazel build 需拉 protobuf，GitHub 不稳。待网络良好时重跑

---

## 10. 开发环境现状

| 项 | 状态 | 位置 |
|----|------|------|
| gVisor 源码 | ✅ 已获取 | `~/dev/gvisor` (WSL2) |
| Go 1.22 | ✅ | `/usr/bin/go` |
| Bazel 8.8.1 | ✅ | `~/.local/bin/bazel` |
| `bazel build //:runsc` | ⚠️ 卡在 protobuf 下载 | 需 GitHub 可达 |
| 阅读代码 | ✅ | 不依赖 build |

**结论**：代码阅读不依赖 bazel build 成功。集成开发（阶段 4b）时需先解决 bazel 镜像。方案：配 `BAZEL_PATH` 指向本地镜像，或直接用 gVisor 预构建的 `runsc` binary 验证。
