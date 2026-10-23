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

> TODO: 读 `pkg/sentry/vfs/` 和 `pkg/sentry/devices/nvproxy/` 后填写

- [ ] Device 接口定义（`Open/Read/Write/Ioctl` 方法签名）
- [ ] 设备注册时机（`platform.Init` 阶段？）
- [ ] fd table 与 device 绑定
- [ ] Ioctl 分发的具体路径

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
