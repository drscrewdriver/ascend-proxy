# 昇腾 NPU ioctl 目录（ascend-ioctl-catalog）

> 数据来源：CANN 9.1.0 / 昇腾 910B2 / ARM aarch64 实测
> 抓取方法：strace -ff + libascend_hal.so 二进制反汇编
> 负载 A：torch_npu 矩阵乘法 (`torch.randn(64,64,device='npu:0').mm(...)`)
> 负载 B：ACL ctypes 直接调用 (`libascendcl.so` — 内存/流/事件/异常)
> 合并统计：strace 覆盖 43 种 + 二进制补全 38 种 = 81 种

---

## 1. 设备文件总览

| 设备 | 主:次号 | 角色 | open 权限 | ioctl 数量 |
|------|---------|------|-----------|-----------|
| `/dev/davinci_manager` | 504:0 | 设备管理器（主 ioctl 通道） | O_RDWR | ~75 种 |
| `/dev/davinci1` | 503:1 | NPU 计算设备 | O_RDONLY | 归属不明（fd 复用） |
| `/dev/hisi_hdc` | 501:0 | 高速数据通道（Host↔Device） | O_RDWR | 9 种（strace 确认 6 种） |
| `/dev/devmm_svm` | 502:0 | 虚拟内存管理 | 权限不足 | 未抓到 |

---

## 2. Magic 号与功能族映射

| Magic | 设备 | 功能族 | 来源 | ioctl 数 | 分发函数 |
|-------|------|--------|------|---------|---------|
| 0x45 | davinci_manager | 初始化/管理 | strace | 2 | 未知 |
| 0x4d | davinci_manager | 核心命令（最密集） | strace + 二进制 | 45+ | `dmanage_common_ioctl` |
| 0x55 | davinci_manager | 设备能力读写 | strace | 2 | 未知 |
| 0x57 | davinci_manager | 配置参数查询 | strace | 6 | 未知 |
| 0x58 | davinci_manager | 设备属性操作 | strace | 10 | CANN 上层库 |
| 0x5a | davinci_manager | 扩展命令 | 二进制 | 2 | `ioctl@plt` 直接调用 |
| 0x89 | 未知 | 未知 | 二进制 | 6 | `ioctl@plt` 直接调用 |
| 0x48 | hisi_hdc | 高速通道控制 | strace | 9 | 未知 |

### 0x58 族来源分析
0x58 族 ioctl 不在 `libascend_hal.so` 驱动层，而在 CANN 上层库中：
- `libccl_kernel.so`：240 处引用（集合通信）
- `libkernel_load_platform.so`：137 处引用（算子内核加载）
- `libplatform.so`：24 处引用（设备平台层）
- `libregister.so`：22 处引用（算子注册）

---

## 3. davinci_manager ioctl 详细目录

### 3.1 Magic 0x45 — 初始化/管理族（2 种）

| 方向 | nr | size | 来源 | 推测功能 | 安全等级 |
|------|-----|------|------|---------|---------|
| NONE | 0x17 | 0 | strace | **初始化/解锁**（时序第一个） | 安全 |
| NONE | 0x1d | 0 | strace | 设备状态查询 | 安全 |

**关键发现**：`_IOC(NONE, 0x45, 0x17, 0)` 是 fd=5 上第一个成功的 ioctl，后续所有 ioctl 才能执行。这是驱动的"握手/解锁"命令。

### 3.2 Magic 0x4d — 核心命令族（45+ 种）

由 `dmanage_common_ioctl`（地址 0x48c2c）统一分发。

#### 3.2.1 NONE 方向（size=0，纯命令）

| nr | 二进制 | strace | 推测功能 | 安全等级 |
|----|--------|--------|---------|---------|
| 0x03 | | ✅ | 设备初始化 | 安全 |
| 0x11 | | ✅ | 上下文创建 | 安全 |
| 0x12 | | ✅ | 上下文查询 | 安全 |
| 0x14 | | ✅ | 资源查询 | 安全 |
| 0x15 | ✅ | | 未知 | 待验证 |
| 0x16 | ✅ | | 未知 | 待验证 |
| 0x1d | ✅ | | 未知 | 待验证 |
| 0x1e | ✅ | | 未知 | 待验证 |
| 0x20 | ✅ | | 未知 | 待验证 |
| 0x33 | ✅ | | 未知 | 待验证 |
| 0x35 | ✅ | | 未知 | 待验证 |
| 0x36 | ✅ | | 未知 | 待验证 |
| 0x3a | | ✅ | 设备属性查询 | 安全 |
| 0x3b | ✅ | ✅ | **双方确认** — 设备状态 | 安全 |
| 0x3f | ✅ | | 未知 | 待验证 |
| 0x4c | ✅ | | 未知 | 待验证 |
| 0x4d | ✅ | | 未知 | 待验证 |
| 0x51 | ✅ | | 未知 | 待验证 |
| 0x56 | ✅ | | 未知 | 待验证 |
| 0x5a | ✅ | | 未知 | 待验证 |
| 0x5b | ✅ | | 未知 | 待验证 |
| 0x5c | ✅ | | 未知 | 待验证 |
| 0x61 | ✅ | | 未知 | 待验证 |
| 0x62 | ✅ | | 未知 | 待验证 |
| 0x64 | ✅ | | 未知 | 待验证 |
| 0x68 | ✅ | | 未知 | 待验证 |
| 0x69 | ✅ | | 未知 | 待验证 |
| 0x6a | ✅ | | 未知 | 待验证 |
| 0x6c | | ✅ | 设备同步 | 安全 |
| 0x70 | ✅ | ✅ | **双方确认** — 设备能力查询 | 安全 |
| 0x74 | ✅ | | 未知 | 待验证 |
| 0x76 | ✅ | | 未知 | 待验证 |
| 0x94 | ✅ | | 未知 | 待验证 |
| 0x9a | ✅ | ✅ | **双方确认** | 安全 |
| 0x9e | ✅ | | 未知 | 待验证 |
| 0x9f | ✅ | | 未知 | 待验证 |
| 0xa0 | ✅ | | 未知 | 待验证 |
| 0xa3 | | ✅ | 资源分配 | 受限 |
| 0xaf | ✅ | ✅ | **双方确认** | 受限 |
| 0xb6 | | ✅ | 资源释放 | 受限 |
| 0xb9 | ✅ | | 未知 | 待验证 |

#### 3.2.2 RW 方向（size=0x158=344 字节，数据交换）

| nr | size | 来源 | 推测功能 | 安全等级 |
|----|------|------|---------|---------|
| 0x05 | 0x158 | strace | 设备信息查询 | 安全 |
| 0x0b | 0x158 | strace | 上下文参数读写 | 受限 |
| 0x0f | 0x158 | strace | 资源状态查询 | 安全 |
| 0x11 | 0x158 | strace | 配置参数读写 | 受限 |
| 0x1a | 0x158 | strace | 流/事件参数 | 受限 |
| 0x23 | 0x158 | strace | 内存映射参数 | 危险 |
| 0x2d | 0x158 | strace | 模型加载参数 | 受限 |
| 0x2e | 0x158 | strace | 推理执行参数 | 受限 |
| 0x31 | 0x158 | strace | 结果查询 | 安全 |
| 0x43 | 0x158 | strace | 未知 | 待验证 |

**注意**：所有 RW 方向的 0x4d 族 ioctl 统一使用 344 字节结构体，推测是通用的 `dmanage_cmd_param` 结构。

### 3.3 Magic 0x55 — 设备能力读写族（2 种）

| 方向 | nr | size | 推测功能 | 安全等级 |
|------|-----|------|---------|---------|
| READ | 0x00 | 0x14 (20B) | 读取设备能力标志 | 安全 |
| WRITE | 0x01 | 0x04 (4B) | 设置设备模式 | 受限 |

**时序**：在初始化（0x45 族）之后立即调用，属于设备能力发现阶段。

### 3.4 Magic 0x57 — 配置参数查询族（6 种）

| 方向 | nr | size | 推测功能 | 安全等级 |
|------|-----|------|---------|---------|
| RW | 0x01 | 0x08 | 配置参数读 | 安全 |
| RW | 0x04 | 0x08 | 配置参数读 | 安全 |
| RW | 0x07 | 0x08 | 配置参数读 | 安全 |
| RW | 0x08 | 0x08 | 配置参数读 | 安全 |
| RW | 0x09 | 0x08 | 配置参数读 | 安全 |
| RW | 0x0c | 0x08 | 配置参数读 | 安全 |

**特征**：统一 8 字节数据，典型的 key-value 配置查询模式。

### 3.5 Magic 0x58 — 设备属性操作族（10 种）

来源：CANN 上层库（libkernel_load_platform.so / libplatform.so）

| 方向 | nr | size | 推测功能 | 安全等级 |
|------|-----|------|---------|---------|
| RW | 0x00 | 0x1c (28B) | 设备属性查询 | 安全 |
| WRITE | 0x01 | 0x1c (28B) | 设备属性设置 | 受限 |
| RW | 0x05 | 0x1c (28B) | 平台参数读写（高频） | 受限 |
| RW | 0x0a | 0x1c (28B) | 未知 | 待验证 |
| RW | 0x0b | 0x04 (4B) | 开关量查询 | 安全 |
| RW | 0x0c | 0x08 (8B) | 计数器查询 | 安全 |
| RW | 0x0d | 0x108 (264B) | 大数据块传输 | 危险 |
| RW | 0x0f | 0x5c (92B) | 配置块读写 | 受限 |
| WRITE | 0x10 | 0x34 (52B) | 未知 | 待验证 |
| RW | 0x12 | 0x34 (52B) | 未知 | 待验证 |

**时序**：在设备初始化完成后调用，属于算子加载/执行阶段。

### 3.6 Magic 0x5a — 扩展命令族（2 种，二进制独有）

| 方向 | nr | size | 推测功能 | 安全等级 |
|------|-----|------|---------|---------|
| 未知 | 0x00 | 未知 | 扩展功能入口 | 待验证 |
| 未知 | 0x01 | 未知 | 扩展功能入口 | 待验证 |

### 3.7 Magic 0x89 — 未知族（6 种，二进制独有）

| nr | 推测功能 | 安全等级 |
|----|---------|---------|
| 0x0b | 未知 | 待验证 |
| 0x0c | 未知 | 待验证 |
| 0x13 | 未知 | 待验证 |
| 0x14 | 未知 | 待验证 |
| 0x16 | 未知 | 待验证 |
| 0x1c | 未知 | 待验证 |

---

## 4. hisi_hdc ioctl 目录（Magic 0x48，9 种）

| 方向 | nr | size | strace | 二进制 | 推测功能 | 安全等级 |
|------|-----|------|--------|--------|---------|----------|
| NONE | 0x07 | 0 | ✅ | | HDC 通道初始化 | 安全 |
| NONE | 0x08 | 0 | ✅ | | HDC 通道配置 | 安全 |
| NONE | 0x10 | 0 | 仅 torch_npu | | HDC 数据传输准备 | 受限 |
| NONE | 0x13 | 0 | ✅ | | HDC 状态查询（高频） | 安全 |
| NONE | 0x17 | 0 | ✅ | | HDC 数据传输 | 受限 |
| NONE | 0x18 | 0 | ✅ | | HDC 完成确认 | 安全 |
| NONE | 0x1d | 0 | ✅ | | HDC 通道关闭 | 安全 |
| NONE | 0x42 | 0 | 仅 torch_npu | | HDC 扩展命令 | 待验证 |
| NONE | 0x43 | 0 | 仅 torch_npu | | HDC 扩展命令 | 待验证 |

**特征**：全部 NONE 方向，纯命令无数据传输。HDC 是 Host-Device Communication 通道，用于在 host 和 NPU 之间传输控制消息。

**ACL ctypes 验证**：纯 ACL 调用（不经过 torch_npu）仅触发 6 种（0x07/0x08/0x13/0x17/0x18/0x1d），缺失的 0x10/0x42/0x43 需要 torch_npu 的完整推理路径才能触发。

---

## 5. 初始化时序（从 strace 推断）

```
阶段 1: 设备打开
  open("/dev/davinci_manager", O_RDWR|O_CLOEXEC) = 3
  open("/dev/davinci_manager", O_RDWR|O_CLOEXEC) = 4
  open("/dev/davinci_manager", O_RDWR|O_CLOEXEC) = 5
  open("/dev/davinci1", O_RDONLY) = 5  (fd 复用)
  open("/dev/hisi_hdc", O_RDWR) = 6

阶段 2: 初始化握手（fd=5）
  ioctl(5, _IOC(NONE, 0x45, 0x17, 0))  ← 🔑 解锁 ioctl

阶段 3: 设备能力发现（fd=4）
  ioctl(4, _IOC(READ, 0x55, 0x00, 0x14))   ← 读设备能力
  ioctl(4, _IOC(WRITE, 0x55, 0x01, 0x04))  ← 设置模式

阶段 4: HDC 通道建立（fd=6）
  ioctl(6, _IOC(NONE, 0x48, 0x07, 0))  ← HDC init
  ioctl(6, _IOC(NONE, 0x48, 0x08, 0))  ← HDC config
  ioctl(6, _IOC(NONE, 0x48, 0x13, 0))  ← HDC status

阶段 5: 设备操作（fd=13，新开的 davinci_manager）
  ioctl(13, _IOC(RW, 0x58, 0x0c, 0x08))   ← 计数器查询
  ioctl(13, _IOC(RW, 0x58, 0x05, 0x1c))   ← 平台参数（×8 次）
  ioctl(13, _IOC(RW, 0x58, 0x0b, 0x04))   ← 开关量
  ioctl(13, _IOC(RW, 0x58, 0x00, 0x1c))   ← 属性查询
  ioctl(13, _IOC(RW, 0x58, 0x0f, 0x5c))   ← 配置块
  ioctl(13, _IOC(WRITE, 0x58, 0x0a, 0x1c)) ← 属性设置
  ioctl(13, _IOC(RW, 0x58, 0x12, 0x34))   ← 未知

阶段 6: 核心命令密集调用（fd=4/5）
  0x4d 族 NONE 方向：0x03, 0x14, 0x3a, 0x3b, 0x6c, 0x70, 0x9a, 0xa3, 0xaf, 0xb6
  0x4d 族 RW 方向：0x05, 0x0b, 0x0f, 0x11, 0x1a, 0x23, 0x2d, 0x2e, 0x31, 0x43
```

---

## 6. 关键函数符号与反汇编分析

| 函数名 | 地址 | 功能 | 调用方式 |
|--------|------|------|----------|
| `dmanage_common_ioctl` | 0x48c2c | davinci_manager ioctl 总分发 | 直接 `ioctl@plt` |
| `DmsIoctl` | 0x5aad8 | DMS 设备管理 ioctl | 直接 `ioctl@plt` |
| `eSchedDevIoctl` | 0x83254 | 调度设备 ioctl | 间接：dispatch table → `halEschedSubmitEventSync` |
| `trsDevIoctl` | 0xdc898 | 传输层设备 ioctl | `ioctl@plt` + EINTR 重试（最多 4 次） |
| `trsDevOpenIoctl` | 0xdca30 | 传输层设备打开 ioctl | 同上 |
| `devmm_svm_ioctl` | 0xebe50 | 虚拟内存管理 ioctl | 直接 `ioctl@plt` |
| `shridIoctl` | 0xe7388 | 共享资源 ioctl | 直接 `ioctl@plt` |
| `dpProcMngIoctl` | 0x12308c | 进程管理 ioctl | 直接 `ioctl@plt` |
| `hdcInit` | 0x8d750 | HDC 通道初始化 | 间接：`halHdcServerWakeUp` |
| `dmanage_dmp_init` | 0x42c94 | DMP 初始化 | — |
| `dmanage_mmIoctl` | 0x48ea0 | 内存管理 ioctl | 直接 `ioctl@plt` |

### 函数调用模式分类

```
模式 A：直接 ioctl 分发
  调用者 → dmanage_common_ioctl(fd, cmd, arg) → ioctl@plt(fd, cmd, arg)
  适用：0x4d 族全部 ioctl

模式 B：事件提交（不直接 ioctl）
  调用者 → eSchedDevIoctl(fd, cmd, arg) → dispatch_table[cmd] → halEschedSubmitEventSync(...)
  适用：调度相关 ioctl

模式 C：重试包装
  调用者 → trsDevIoctl(fd, cmd, arg) → ioctl@plt(fd, cmd, arg) [EINTR 重试 ≤4 次]
  适用：传输层 ioctl

模式 D：间接初始化
  调用者 → hdcInit(...) → share_log_create + halHdcServerWakeUp
  适用：HDC 通道建立
```

---

## 7. 安全等级分类汇总

### 安全（白名单放行）— 28 种
- 0x45 族：0x17, 0x1d（初始化/管理）
- 0x4d NONE 族（查询类）：0x03, 0x11, 0x12, 0x14, 0x3a, 0x3b, 0x6c, 0x70, 0x9a
- 0x4d RW 族（只读查询）：0x05, 0x0f, 0x31
- 0x55 READ：0x00
- 0x57 全部：0x01, 0x04, 0x07, 0x08, 0x09, 0x0c
- 0x58 RW（小数据量查询）：0x00, 0x0b, 0x0c
- 0x48 HDC（控制命令）：0x07, 0x08, 0x13, 0x18, 0x1d

### 受限（需配额/审计）— 16 种
- 0x4d RW 族（参数读写）：0x0b, 0x11, 0x1a, 0x2d, 0x2e
- 0x4d NONE 族（资源操作）：0xa3, 0xaf, 0xb6
- 0x55 WRITE：0x01
- 0x58 RW（中等数据量）：0x05, 0x0a, 0x0f, 0x10, 0x12
- 0x58 WRITE：0x01
- 0x48 HDC（数据传输）：0x10, 0x17

### 危险（黑名单拒绝）— 2 种
- 0x4d RW 族（内存映射）：0x23
- 0x58 RW（大数据块）：0x0d（264 字节，可能传输固件/配置）

### 待验证 — 38+ 种
- 0x4d 族二进制独有（29 种）
- 0x5a 族（2 种）
- 0x89 族（6 种）
- 0x48 HDC 扩展（0x42, 0x43）

---

## 8. ACL ctypes 交叉验证

> 时间：2026-10-24，在 AutoDL 昇腾 910B2 实例上通过 `ctypes.CDLL('libascendcl.so')` 直接调用 ACL API

### 8.1 负载覆盖

| 族 | 负载内容 | 结果 |
|----|---------|------|
| B 内存 | `aclrtMalloc(64/256/1K/4K/1M/4M)` + `aclrtFree` | ✅ 成功，触发 9 条 ioctl |
| C 流/事件 | `aclrtCreateStream` ×4 + `SynchronizeStream` + `CreateEvent` ×4 | ⚠️ 部分成功，`RecordEvent` 时 segfault |
| D 矩阵运算 | 未跑（容器无 torch） | — |
| E 模型推理 | 未跑（无 .om 模型） | — |
| F 多卡通信 | 未跑（单卡环境） | — |
| G 异常路径 | `Malloc(60GB)` + `Free(NULL)` + `SetDevice(99)` + `Memcpy overflow` | ✅ 全部返回错误码，触发 9 条 ioctl |

### 8.2 ACL ctypes vs torch_npu 对比

| ioctl | ACL ctypes | torch_npu | 说明 |
|-------|-----------|-----------|------|
| 0x4d NONE nr=0x03 | ✅ | ✅ | 双方均触发（设备初始化） |
| 0x4d RW nr=0x11 | ✅ | ✅ | ACL 触发 RW 方向，torch 触发 NONE 方向 |
| 0x4d NONE nr=0x12 | ❌ | ✅ | 仅 torch_npu 触发（上下文查询） |
| 0x4d NONE nr=0xa3 | ❌ | ✅ | 仅 torch_npu 触发（资源分配） |
| 0x4d NONE nr=0xaf | ❌ | ✅ | 仅 torch_npu 触发 |
| 0x45 NONE nr=0x1d | ❌ | ✅ | 仅 torch_npu 触发（设备状态查询） |
| 0x48 NONE nr=0x10 | ❌ | ✅ | 仅 torch_npu 的完整推理路径触发 |
| 0x48 NONE nr=0x42/0x43 | ❌ | ✅ | 仅 torch_npu 触发 |

### 8.3 初始化时序（ACL ctypes 实测）

```
[0] 0x55 READ  nr=0x00  ← 第一个 ioctl，读设备能力
[1] 0x55 WRITE nr=0x01  ← 设置设备模式
[2] 0x4d NONE  nr=0x6c  ← 设备管理命令
[5] 0x4d NONE  nr=0x9a  ← 设备管理命令
[6-8] 0x4d NONE nr=0x03 × 3  ← 设备初始化（重复 3 次）
[9] 0x45 NONE  nr=0x17  ← 🔑 解锁 ioctl
[10-11] 0x4d NONE nr=0x14 × 2  ← 资源查询
```

**关键发现**：0x55 READ nr=0x00 是全局第一个 ioctl（早于 0x45 解锁），说明设备能力探测在解锁之前。

---

## 9. 统计

| 指标 | 数值 |
|------|------|
| 总 magic 号数 | 8 |
| 总 ioctl 种类（去重） | ~81 |
| strace 抓到的（torch_npu + ACL ctypes 合并） | 43 |
| 二进制独有（strace 未触发） | 38 |
| 双方确认的 | 4 |
| 已分类安全等级 | 43 |
| 待验证 | 38 |
| 仅 torch_npu 能触发的 | 7（nr=0x12/0xa3/0xaf/0x1d/0x10/0x42/0x43） |

---

## 10. 下一步

1. **torch_npu 环境补抓**：安装 torch/torch_npu 后重跑，补全 7 种专属 ioctl
2. **结构体推断**：根据 size 字段推断每个 ioctl 的参数结构体布局
3. **0x5a/0x89 族归属**：确定这两个 magic 号对应的设备和功能
4. **devmm_svm ioctl**：获取 `/dev/devmm_svm` 的访问权限后抓取虚拟内存管理 ioctl
5. **白名单精化**：根据安全等级分类实现 proxy 的过滤规则
6. **阶段二启动**：基于 43 种已确认 ioctl 编写 proxy 骨架
