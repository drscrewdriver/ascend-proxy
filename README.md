# ascend-proxy

昇腾 NPU ioctl 代理层 — 模仿 gVisor `--nvproxy` 思路，为昇腾 NPU 构建用户态 ioctl 代理，让沙箱容器能安全访问 NPU 设备。

> **状态**: 阶段一（抓接口）进行中
> **环境**: CANN 9.1.0 / 昇腾 910B2 / ARM aarch64

---

## 项目目标

```
容器进程 → ascend-oci-runtime（OCI wrapper）
                │
                ├── 修改 OCI spec：注入代理设备
                ├── 启动 ascend-ioctl-proxy
                └── 调用 runc 创建容器
                         │
ascend-ioctl-proxy ←─────┘
    │
    ├── 白名单过滤 ioctl（只放行 NPU 安全操作）
    ├── 拒绝危险 ioctl（写内存/改配置）
    └── 转发给真正的 /dev/davinciX
              │
         宿主机 ascend 驱动 → NPU 硬件
```

## 项目结构

```
ascend-proxy/
├── README.md                    # 本文件
├── docs/
│   ├── ascend-ioctl-catalog.md  # ioctl 接口目录（阶段一核心交付物）
│   └── learning-plan.md         # 学习计划与路线图
├── tools/
│   └── extract_npu_ioctl.py     # strace 日志解析脚本
└── (future)
    ├── proxy/                   # 阶段二：ioctl 代理核心
    ├── runtime/                 # 阶段三：OCI runtime wrapper
    └── tests/                   # 测试用例
```

## 四阶段路线

| 阶段 | 周期 | 目标 | 状态 |
|------|------|------|------|
| 一：抓接口 | 1-2 周 | strace + 二进制逆向 → ioctl catalog | 🔄 进行中 |
| 二：最小代理 | 2-3 周 | C/Rust 写 proxy，白名单转发 | ⏳ 待开始 |
| 三：OCI Runtime | 1-2 周 | ascend-oci-runtime wrapper | ⏳ 待开始 |
| 四：沙箱集成 | 2-3 周 | gVisor/seccomp 集成 | ⏳ 待开始 |

## 阶段一成果

### ioctl 目录

通过 strace 运行时抓取 + libascend_hal.so 二进制反汇编，已识别：

| 指标 | 数值 |
|------|------|
| 总 magic 号 | 8 个 |
| 总 ioctl 种类 | ~84 种 |
| strace 抓到 | 46 种 |
| 二进制独有 | 38 种 |
| 已标注安全等级 | 46 种 |

### 设备文件

| 设备 | Magic 号 | ioctl 数量 |
|------|---------|-----------|
| `/dev/davinci_manager` | 0x45, 0x4d, 0x55, 0x57, 0x58, 0x5a, 0x89 | ~75 |
| `/dev/hisi_hdc` | 0x48 | 9 |

### 关键函数

- `dmanage_common_ioctl` — davinci_manager ioctl 总分发器
- `eSchedDevIoctl` — 调度设备 ioctl（事件提交模式）
- `trsDevIoctl` — 传输层 ioctl（EINTR 重试包装）
- `hdcInit` — HDC 通道初始化

详细目录见 [docs/ascend-ioctl-catalog.md](docs/ascend-ioctl-catalog.md)

## 参考

| 项目 | 参考点 |
|------|--------|
| [gVisor nvproxy](https://gvisor.dev/) | ioctl 代理思路 |
| [nvidia-container-runtime](https://github.com/NVIDIA/nvidia-container-toolkit) | OCI wrapper 实现 |
| [ascend-docker-runtime](https://gitee.com/ascend/docker-runtime) | 昇腾设备挂载逻辑 |
| [HAMi](https://project-hami.io/) | NPU 切分共享 |

## License

MIT
