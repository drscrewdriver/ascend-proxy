# gVisor 集成目录

本目录存放 **ascendproxy Go 模块骨架**，目标是在阶段 4b 时整体拷入 gVisor fork 的 `pkg/sentry/devices/ascendproxy/`。

## 当前状态

**Phase 3 W8 骨架阶段** — 代码在本地编译不能通过（gVisor 依赖未拉全），但设计完整可评审。

## 结构

```
gvisor-integration/pkg/sentry/devices/ascendproxy/
├── ascendproxy.go          — Register(vfsObj, opts) 主入口
├── fd.go                    — davinciFD + Ioctl 分发器
├── abi910.go                — 80 条 ioctl 白名单（CANN 9.1.0）
├── seccomp_filter.go        — Filters() 供 Sentry 自身使用
├── ascendproxy_unsafe.go   — unsafe.Pointer 隔离
└── ascendconf/ascendconf.go — Caps 位掩码定义
```

## 与阶段二 C 代码的关系

| 阶段二产物 | 集成路径归宿 |
|-----------|-------------|
| `whitelist.c` 80 条数据 | ✅ 转成 `abi910.go` 的 `ioctlMap` |
| `proxy_main.c` supervisor | ❌ 不需要（Sentry 就是 supervisor） |
| `inject_seccomp.c` LD_PRELOAD | ❌ 不需要（Sentry 天然拦截） |
| `docs/ascend-ioctl-catalog.md` | ✅ 作为 `abi910.go` 生成的数据源 |
| `tests/test_workload.py` | ✅ 端到端测试保留 |

C 分支保留在 `src/` 和 `tests/`，作为**独立可部署形态**（Kata 场景），与 gVisor 分支并存。

## 后续待补

- [ ] `davinci.go` 里的 `davinciDevice.Open` 完整实现（需要 gVisor host package API）
- [ ] `hdc.go` 类似实现
- [ ] `runsc/config/config.go` 加 `--ascendproxy` flag
- [ ] `runsc/specutils/ascend.go` `AscendProxyEnabled()`
- [ ] `runsc/boot/vfs.go` 加 `ascendproxyRegisterDevices()` 平行函数
- [ ] `BUILD.bazel` 文件

## 参考

- `docs/gvisor-integration-analysis.md` — 架构决策依据
- `docs/nvproxy-annotated.md` — nvproxy 精读笔记
- `docs/learning-plan.md` §阶段四 — 时间表

## 如何拷入 gVisor fork

```bash
# 假设 gVisor 在 ~/dev/gvisor (a git fork)
cp -r gvisor-integration/pkg/sentry/devices/ascendproxy ~/dev/gvisor/pkg/sentry/devices/
cd ~/dev/gvisor
# 补全 Open 方法后
bazel build //pkg/sentry/devices/ascendproxy:ascendproxy
```
