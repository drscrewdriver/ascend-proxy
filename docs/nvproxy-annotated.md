# nvproxy/rdmaproxy/tpuproxy 精读笔记

> 目标：为 ascendproxy 集成提炼最小可行 device 模块模板
> 参考代码：`~/dev/gvisor/pkg/sentry/devices/{nvproxy,rdmaproxy,tpuproxy}/`
> 阅读日期：2026-10-24

---

## 1. 复杂度对比

| 模块 | 总行数 | 定位 | 参考度 |
|------|-------|------|-------|
| tpuproxy | 235 | 最小示例 | ⭐⭐⭐⭐⭐ 起手模板 |
| rdmaproxy | 2440 | 中等：单一 device 多 ioctl | ⭐⭐⭐⭐ 结构参考 |
| nvproxy | 7593 | 复杂：object tracking + ABI 版本 | ⭐⭐ 后期参考 |

**推荐学习顺序**：tpuproxy 起步 → rdmaproxy 学 ioctl handler → nvproxy 学高级特性。

---

## 2. 最小 device 模板（从 tpuproxy 提炼）

### 2.1 三件套

一个完整 device 只需 3 段：

```go
package ascendproxy

// ① 设备类型 + Open 方法（对应 vfs.Device 接口）
type davinciDevice struct {
    minor uint32
}

func (dev *davinciDevice) Open(ctx context.Context, mnt *vfs.Mount,
    vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
    // 打开真 host fd
    hostFD, err := unix.Open(dev.path(), unix.O_RDWR, 0)
    if err != nil {
        return nil, err
    }
    // 返回给容器使用的 fd 对象
    return &davinciFD{hostFD: hostFD}, nil
}

// ② 文件描述符 + Ioctl 方法（对应 vfs.FileDescription 接口）
type davinciFD struct {
    vfs.PrefixedFD
    hostFD int
    mu     sync.Mutex
}

func (fd *davinciFD) Ioctl(ctx context.Context, uio usermem.IO,
    sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
    cmd := args[1].Uint()
    magic := linux.IOC_TYPE(cmd)

    // 白名单查询
    if !isWhitelisted(magic, linux.IOC_NR(cmd)) {
        return 0, linuxerr.EPERM
    }

    // 通过 seccomp filter 后，这里 RawSyscall 是被允许的
    n, _, errno := unix.RawSyscall(unix.SYS_IOCTL,
        uintptr(fd.hostFD), uintptr(cmd), args[2].Pointer())
    runtime.KeepAlive(fd)
    if errno != 0 {
        return 0, errno.ToLinuxError()
    }
    return uintptr(n), nil
}

// ③ Sentry 自身的 seccomp 白名单
func Filters() seccomp.SyscallRules {
    return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
        unix.SYS_IOCTL: seccomp.Or{
            // 逐个枚举 80 种允许的 ioctl
            seccomp.EqualTo(0x00004517),
            seccomp.EqualTo(0x00004d03),
            // ...
        },
        // openat 只允许打开 davinci_manager 和 hisi_hdc
        unix.SYS_OPENAT: seccomp.PerArg{
            seccomp.EqualTo(^uintptr(0)),
            seccomp.AnyValue{},   // TODO: 精确匹配路径
            seccomp.EqualTo(unix.O_RDWR|unix.O_CLOEXEC),
        },
    })
}
```

**总代码量估算**：tpuproxy 级别的简洁版 ~250 行 Go。

### 2.2 注册入口

```go
// Register 在 Sentry 启动时被 loader.go 调用
func Register(vfsObj *vfs.VirtualFilesystem, opts *Options) error {
    // 打开 davinci_manager
    if err := vfsObj.RegisterDevice(
        vfs.CharDevice,
        DAVINCI_MANAGER_MAJOR,   // 504
        DAVINCI_MANAGER_MINOR,   // 0
        &davinciDevice{...},
        &vfs.RegisterDeviceOptions{
            Directory:  "",
            PathName:   "/dev/davinci_manager",
            MaxLength:  len("/dev/davinci_manager"),
        }); err != nil {
        return err
    }
    // 打开 hisi_hdc
    // ...
    return nil
}
```

关键 API：`vfsObj.RegisterDevice(major=CharDevice, major#, minor#, dev, opts)`

---

## 3. rdmaproxy 学到的 ioctl handler 模式

`rdmaproxy/ioctl.go` 660 行，模式：

```go
// 每个 ioctl 一个独立 handler
func (fd *uverbsFD) ioctlQueryDevice(ctx context.Context, arg uint64) error {
    var params ib.UVERBS_METHOD_INFO
    if err := copyInParams(fd.t, arg, &params); err != nil {
        return err
    }

    // ... Sentry 内部处理（可查询/修改 params）...

    // 转发到真 ioctl
    _, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd.hostFD), ioctlCmd, arg)
    if errno != 0 {
        return errno.ToLinuxError()
    }
    return copyOutParams(fd.t, arg, &params)
}

// 主 Ioctl 用 switch 分发
func (fd *uverbsFD) Ioctl(ctx, ...) (uintptr, error) {
    switch cmd {
    case IB_UVERBS_METHOD_INFO:
        return 0, fd.ioctlQueryDevice(ctx, args[2].Uint())
    // ...
    }
    return 0, linuxerr.ENOTTY
}
```

**优点**：每个 ioctl 独立函数，可精确处理参数结构。

**对我们的映射**：80 种 ioctl → 大致 80 个 handler。但大部分可以直接用 generic `frontendIoctlSimple` 模式（不解析参数，只 CopyIn → RawSyscall → CopyOut）。只有少数需要精细化的（比如 0x4d RW size=0x158 的通用参数块）需要单独写。

---

## 4. nvproxy 的高级特性（后续可选）

### 4.1 Capability 掩码（值得抄）

```go
type frontendIoctlHandler struct {
    handler func(*frontendIoctlState) (uintptr, error)
    capSet  nvconf.DriverCaps    // 位掩码
}
```

对我们：`type Cap uint32` + `const ( CapInfer Cap = 1<<0; CapTrain Cap = 1<<1; CapHCCL Cap = 1<<2 )`

不同部署（推理/训练/多卡）通过 runsc flag 决定启用哪些。

### 4.2 Object tracking（暂不需要）

nvproxy 追踪 `class/handle/parent/deps` 关系，因为 NVIDIA 驱动本身有对象生命周期依赖。

昇腾 ioctl 是否有类似依赖？— **阶段一数据不足以判断**，需阶段 4b 集成时逐步验证。

初版 ascendproxy 不实现 object tracking，先看容器能否跑通。

### 4.3 Save/Restore（Phase 4b 后期）

nvproxy 有 `save_restore.go` (405 行) + `save_restore_unsafe.go` (184 行)，实现 checkpoint/restore。

我们暂不管，v1 版本禁用CRIU 即可。

---

## 5. ABI 结构体定义风格（pkg/abi/davinci/）

参考 `pkg/abi/nvgpu/` 和 `pkg/abi/ib/`。

**需要为昇腾定义的结构体**：
- 通用 `dmanage_cmd_param`（0x158 = 344 字节，多个 0x4d RW ioctl 共用）
- `dev_attr`（0x1c 字节，0x58 RW 常见）
- `caps_flags`（0x14 字节，0x55 READ nr=0x00）
- `config_block`（0x5c 字节，0x58 RW nr=0x0f）
- 其他 size（0x4/0x8/0x34/0x48/0x108）

**Phase 4b 第一步**：先用 `primitive.ArrayU8` 或 opaque blob 覆盖全部；能跑通再逐步细化。

---

## 6. 阶段 4b 起手任务清单

- [ ] 在 gVisor fork 里创建 `pkg/sentry/devices/ascendproxy/`
- [ ] 实现 `ascendproxy.go` — Register + Options（照抄 tpuproxy 结构）
- [ ] 实现 `davinci.go` — davinciDevice + davinciFD（含 Ioctl）
- [ ] 实现 `hdc.go` — hisi_hdc 同上
- [ ] 生成 `whitelist.go` — 从 catalog.md 抽 80 条 ioctl → seccomp.Or
- [ ] 加 flag `--ascendproxy` 到 `runsc/config/config.go`
- [ ] 修改 `runsc/boot/loader.go` 调 `ascendproxy.Register(vfsObj, opts)`
- [ ] 单元测试：`ascendproxy_test.go`
- [ ] 端到端：runsc 启动一个装了 torch_npu 的容器

**预计代码量**：500-800 行 Go（不含生成）

---

## 7. 与阶段二 C 代码的复用关系

| 阶段二产物 | 阶段 4b 归宿 |
|-----------|------------|
| `whitelist.c` 表 | ✅ 1:1 转成 Go map |
| `proxy_main.c` | ❌ **不需要**，Sentry 就是 supervisor |
| `inject_seccomp.c` | ❌ **不需要**，Sentry 天然拦截 |
| `docs/ascend-ioctl-catalog.md` | ✅ 作为 whitelist.go 的数据源 |
| `tests/check_env.c` | ❌ 用 `runsc --ascendproxy` 直接测 |
| `tests/test_workload.py` | ✅ **保留**，作为端到端测试 |

**意外收获**：阶段二的 C 代码在集成路径里几乎不用了。但**逆向过程本身**（收集的 80 种 ioctl + 时序 + capability 分类）是阶段 4b 唯一的核心资产。这就是学习的价值——代码是副产品，数据+理解才是产物。

---

## 8. 更新日志

- 2026-10-24：首次精读三模块，产出模板 + 复用清单
