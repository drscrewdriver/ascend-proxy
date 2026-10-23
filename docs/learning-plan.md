# ascend-proxy 学习计划：AI+逆向构建昇腾 NPU ioctl 代理层

> 模仿 gVisor `--nvproxy` 思路，为昇腾 NPU 做一个学习级 ioctl 代理层，让沙箱容器能安全访问 NPU 设备。
> 预计总周期：7-11 周（业余时间），AI 辅助可压缩至 5-8 周。

---

## 项目架构

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

---

## 时间表

### 阶段一：抓接口（第 1-2 周）

| 周 | 任务 | 产出 | AI 辅助 |
|----|------|------|---------|
| W1 | 搭建昇腾开发环境（华为云 ModelArts 或本地 Host 侧组件） | 可运行的 NPU 环境 | AI 帮查文档、排错 |
| W1 | 用 strace 追踪容器进程对 `/dev/davinciX` 的 ioctl 调用 | `trace.log` 原始数据 | — |
| W2 | 分析 strace 输出，归类 ioctl 编号和用途 | `ascend-ioctl-catalog.md` | AI 归类 + 生成结构体定义 |
| W2 | 标注每个 ioctl 的安全等级（安全/受限/危险） | 白名单初稿 | AI 辅助判断 |

**阶段产出**：`ascend-ioctl-catalog.md`（含 ioctl 编号、参数结构、安全等级）

---

### 阶段二：最小代理（第 3-5 周）

| 周 | 任务 | 产出 | AI 辅助 |
|----|------|------|---------|
| W3 | 搭建项目骨架（C/Rust），写 FUSE 或 unix socket 框架 | 可编译的空壳 proxy | AI 生成代码框架 |
| W3 | 实现白名单过滤逻辑 | `proxy.c` 核心模块 | AI 生成过滤代码 |
| W4 | 实现 ioctl 转发（白名单内的调用透传给真实设备） | 能跑通简单查询 | AI 调试帮助 |
| W4 | 编写测试用例（模拟容器进程发 ioctl） | `test_ioctl.c` | AI 生成测试代码 |
| W5 | 补全白名单内所有 ioctl 的转发逻辑 | 完整 proxy | AI 批量生成 |
| W5 | 压力测试 + 错误处理 | 稳定版 proxy | AI 分析 crash log |

**阶段产出**：`ascend-ioctl-proxy` 二进制（能代理 NPU 查询、流创建等操作）

---

### 阶段三：gVisor 铺垫（第 6-8 周）

> 方向调整：不再自写 OCI runtime wrapper（gVisor 本身就是完整 OCI runtime），
> 直接以 gVisor 为集成目标。阶段二完成的 C 代理保留为独立分支（可单独部署），
> 阶段三产出为集成铺好的认知地基。

| 周 | 任务 | 产出 | AI 辅助 |
|----|------|------|---------|
| W6 | 搭 gVisor 本地开发环境（Go 1.21+ / bazel / Linux ≥ 5.10） | `bazel test //test/...` 基线全绿 | AI 排错 |
| W6-W7 | 精读 nvproxy 源码（`pkg/sentry/devices/nvproxy/`） | 标注好的代码阅读笔记 | AI 解释 Go 上下文 |
| W7 | 运行官方 nvproxy example（CUDA 容器 in gVisor） | 能复现 NVIDIA 例子的实验记录 | — |
| W7-W8 | 拆解 Sentry device 注册机制（vfs / fdtable / platform） | 文字 + 图 | AI 提炼 |
| W8 | 写 `docs/gvisor-integration-analysis.md`（=阶段 4a 产物） | 集成方案文档 | AI 辅助文档结构 |

**阶段产出**：集成分析文档 + 能熟读 gVisor 代码的能力

---

### 阶段四：gVisor 集成与开源（第 9-14 周）

#### 4a：集成方案设计（已含在阶段三的尾期）

产出：`docs/gvisor-integration-analysis.md`，内容：
- nvproxy 三层分层→ ascend-proxy 对应映射
- Sentry 侧需要的 Go device handler 接口定义
- frontend 协议适配方案（复用阶段二 proxy_main.c）
- 白名单从 catalog 自动导出为 Go 表的脚本

#### 4b：Fork gVisor + ascendproxy 子系统（主体实现）

| 周 | 任务 | 产出 |
|----|------|------|
| W9-W10 | 在 fork 中新增 `pkg/sentry/devices/ascendproxy/` 骨架 | Go 代码模块 + 单元测试 |
| W10 | 实现 `/dev/davinci_manager` 伪设备 (Go) | vfs.Device 接口实现 |
| W10-W11 | 实现 `/dev/hisi_hdc` 伪设备 | 同上 |
| W11 | 适配阶段二 proxy_main.c 为 frontend 协议 | C 代码改造 + 接口测试 |
| W11-W12 | 白名单自动导出：catalog.md → whitelist.go | 代码生成脚本 |
| W12-W13 | 集成测试：`runsc --ascendproxy` + torch_npu | e2e 实验报告 |
| W13 | 安全测试：尝试绕过、伪造 ioctl | 安全测试报告 |
| W13-W14 | 性能基准：直通 vs gVisor+proxy | 对比数据表 |

**产出**：gVisor fork + 可直接 `bazel run //:runsc` 的完整集成

#### 4c：开源发布与文档

| 任务 | 产出 |
|------|------|
| 写 blog 系列：`blog/` 目录，包含逆向→代理→集成三篇 | 技术博客 |
| README 升级：架构图 + 快速开始 + FAQ | 开门户入口 |
| 向 gVisor 上游提 RFC/Issue（先存于自己 fork） | 上游开场 |
| 可选：提交 gvisor.dev 官方 mailing list | 社区互动 |

**产出**：开源项目完整上线 + 可写进简历的集成实现

---

---

## 里程碑总览

```
W1-W2   ████░░░░░░░░░░░░░░░░  阶段一：抓接口 → ioctl catalog ✅
W3-W5   ░░░░██████░░░░░░░░░░  阶段二：最小代理 → proxy 二进制（分支保留）
W6-W8   ░░░░░░░░░░████░░░░░░  阶段三：gVisor 铺垫 → 集成分析文档
W9-W14  ░░░░░░░░░░░░░░██████  阶段四：集成实现 + 开源发布（4a/4b/4c）
```

| 里程碑 | 时间 | 交付物 | 验证标准 |
|--------|------|--------|---------|
| M1 | W2 末 | `ascend-ioctl-catalog.md` | 至少列出 10 个 ioctl 及用途 ✅（实际 80 种） |
| M2 | W5 末 | `ascend-ioctl-proxy` (C 独立分支) | 能代理 3 种以上 ioctl 并返回正确结果 |
| M3 | W8 末 | `docs/gvisor-integration-analysis.md` | 方案可执行 + 接口定义完备 |
| M4 | W14 末 | gVisor fork + `runsc --ascendproxy` | torch_npu 在 gVisor 里能完成推理 |

---

## 工具链

| 用途 | 工具 | 说明 |
|------|------|------|
| 逆向抓包 | strace | 追踪 ioctl 系统调用 |
| 代理开发 | C / Rust | proxy 核心逻辑 |
| OCI wrapper | Go / Rust | 参考 nvidia-container-runtime |
| 沙箱（可选） | gVisor / seccomp | 安全隔离层 |
| 测试环境 | 华为云 ModelArts | 按量计费 Ascend 910 |
| AI 辅助 | Claude / GPT / Qoder | 代码生成 + 文档分析 |

---

## 参考对标

| 项目 | 地址 | 参考点 |
|------|------|--------|
| gVisor `--nvproxy` | https://gvisor.dev/ | ioctl 代理思路 |
| nvidia-container-runtime | https://github.com/NVIDIA/nvidia-container-toolkit | OCI wrapper 实现 |
| ascend-docker-runtime | https://gitee.com/ascend/docker-runtime | 昇腾设备挂载逻辑 |
| HAMi | https://project-hami.io/ | NPU 共享调度 |

---

## 学习价值

```
├── Linux ioctl 机制（系统编程核心）
├── OCI 容器运行时规范（云原生基础设施）
├── 设备驱动接口逆向（安全研究方向）
├── C/Rust + Go 混合编程（系统级开发）
├── gVisor / Kata 沙箱原理（云原生安全）
└── 昇腾 NPU 驱动接口（国产 AI 芯片稀缺经验）
```

---

## 阶段一加速：先看头文件定向验证（最大加速手段）

> 先看 CANN 头文件里的 ioctl 编号定义，定向验证比盲抓快 5 倍。
> 不要上来就 strace 盲抓，先从头文件里拿到 ioctl 编号清单，再有针对性地构造负载验证。

### 第一步：找到 CANN/驱动头文件中的 ioctl 定义

```bash
# CANN 安装后头文件通常在以下位置
CANN_ROOT="/usr/local/Ascend/ascend-toolkit/latest"
DRIVER_ROOT="/usr/local/Ascend/driver"

# 搜索所有包含 ioctl 定义的头文件
find $CANN_ROOT $DRIVER_ROOT -name "*.h" 2>/dev/null | \
  xargs grep -l -i "ioctl\|_IOC\|IOCTL_\|DEVCTRL" 2>/dev/null

# 重点关注这些文件（常见命名模式）
find / -path "*/ascend*" -name "*.h" 2>/dev/null | \
  xargs grep -l "define.*IOC\|define.*IOCTL\|define.*DEVCTRL" 2>/dev/null
```

### 第二步：提取 ioctl 编号

昇腾 ioctl 编号遵循 Linux 标准编码规则：

```c
// Linux ioctl 编号编码（<asm/ioctl.h>）
// _IO(type, nr)         → 无数据
// _IOR(type, nr, size)  → 读（驱动→用户）
// _IOW(type, nr, size)  → 写（用户→驱动）
// _IOWR(type, nr, size) → 读写

// type 是设备魔数（8 bit），nr 是命令号（8 bit）
// 昇腾 davinci 设备的 type 通常是 'd' (0x64) 或自定义值

// 示例：从宏定义中提取编号
#define ASCEND_IOCTL_QUERY_STATUS   _IOR('d', 0x01, struct ascend_status)
#define ASCEND_IOCTL_ALLOC_MEMORY   _IOW('d', 0x10, struct ascend_alloc)
#define ASCEND_IOCTL_FREE_MEMORY    _IOW('d', 0x11, struct ascend_free)
#define ASCEND_IOCTL_CREATE_STREAM  _IOR('d', 0x20, struct ascend_stream)
```

```bash
# 一键提取所有 ioctl 编号定义
grep -rn "define.*_IO\|define.*_IOR\|define.*_IOW\|define.*_IOWR" \
  $CANN_ROOT/include/ $DRIVER_ROOT/include/ 2>/dev/null | \
  awk '{print $2, $3}' | sort

# 或者搜索十六进制硬编码的 ioctl 编号
grep -rn "0x[0-9a-fA-F]\{8\}" \
  $CANN_ROOT/include/ $DRIVER_ROOT/include/ 2>/dev/null | \
  grep -i "ioctl\|cmd\|command"
```

### 第三步：用 Python 解码 ioctl 编号

```python
#!/usr/bin/env python3
"""decode_ascend_ioctl.py - 解码昇腾 ioctl 编号"""

def decode_ioctl(val):
    """解码 Linux ioctl 编号为各字段"""
    direction = (val >> 30) & 0x3   # 2 bit
    size      = (val >> 16) & 0x3FFF # 14 bit
    type_char = (val >> 8) & 0xFF    # 8 bit
    nr        = val & 0xFF           # 8 bit
    
    dir_map = {0: "NONE", 1: "WRITE(_IOW)", 2: "READ(_IOR)", 3: "RW(_IOWR)"}
    
    print(f"ioctl 编号: 0x{val:08X}")
    print(f"  方向: {dir_map.get(direction, 'UNKNOWN')}")
    print(f"  数据大小: {size} bytes")
    print(f"  设备类型: '{chr(type_char)}' (0x{type_char:02X})")
    print(f"  命令号: 0x{nr:02X} ({nr})")
    print()

# 从头文件中提取到的编号（示例，实际需要从头文件读取）
ioctls = [
    0x80086401,  # 可能是 QUERY_STATUS
    0x40106410,  # 可能是 ALLOC_MEMORY
    0x40106411,  # 可能是 FREE_MEMORY
    0x80046420,  # 可能是 CREATE_STREAM
]

for v in ioctls:
    decode_ioctl(v)
```

### 第四步：构造定向抓取计划

拿到编号清单后，按族分类构造触发负载：

```
┌──────────────────────────────────────────────────────────────┐
│ 族 A：设备管理（type='d', nr=0x01-0x0F）                     │
│   触发命令：npu-smi info / npu-smi info -t health             │
│   预计命中：5-8 个 ioctl                                      │
├──────────────────────────────────────────────────────────────┤
│ 族 B：内存操作（type='d', nr=0x10-0x1F）                     │
│   触发方式：写 C 程序调 aclrtMalloc / aclrtFree / aclrtMemcpy │
│   预计命中：5-10 个 ioctl                                     │
├──────────────────────────────────────────────────────────────┤
│ 族 C：流/事件（type='d', nr=0x20-0x2F）                      │
│   触发方式：aclrtCreateStream / aclrtSynchronizeStream        │
│   预计命中：3-5 个 ioctl                                      │
├──────────────────────────────────────────────────────────────┤
│ 族 D：模型执行（type='d', nr=0x30-0x4F）                     │
│   触发方式：加载 .om 模型 → 推理 → 取结果                     │
│   预计命中：5-15 个 ioctl                                     │
├──────────────────────────────────────────────────────────────┤
│ 族 E：模型转换（type='d', nr=0x50-0x5F）                     │
│   触发方式：atc --model=xxx.onnx --output=xxx --soc_version=  │
│   预计命中：3-8 个 ioctl                                      │
├──────────────────────────────────────────────────────────────┤
│ 族 F：多卡通信（type='d', nr=0x60-0x7F）                     │
│   触发方式：HCCL AllReduce / 多卡推理                         │
│   预计命中：3-5 个 ioctl（需 8 卡整机）                       │
├──────────────────────────────────────────────────────────────┤
│ 族 G：异常路径（散落各 nr 段）                                │
│   触发方式：故意 OOM / 非法地址 / 设备故障                    │
│   预计命中：2-5 个 ioctl                                      │
└──────────────────────────────────────────────────────────────┘
```

### 第五步：定向验证脚本

```bash
#!/bin/bash
# ascend_ioctl_capture.sh - 按族定向抓取 ioctl
# 用法：在昇腾环境上运行，自动触发各类 ioctl 并记录

set -e
TRACE_DIR="/tmp/ascend_ioctl_traces"
mkdir -p $TRACE_DIR

echo "=== [族 A] 设备管理 ioctl ==="
strace -f -e trace=ioctl -o $TRACE_DIR/01_device_query.log \
  npu-smi info -l 2>/dev/null || true

echo "=== [族 B] 内存操作 ioctl ==="
strace -f -e trace=ioctl -o $TRACE_DIR/02_memory_ops.log \
  python3 -c "
import ctypes
lib = ctypes.CDLL('libascendcl.so')
lib.aclInit(None)
lib.aclrtSetDevice(0)
# 分配 + 拷贝 + 释放
buf = ctypes.c_void_p()
lib.aclrtMalloc(ctypes.byref(buf), 1024*1024, 0)
lib.aclrtFree(buf)
lib.aclrtResetDevice(0)
lib.aclFinalize()
" 2>/dev/null || true

echo "=== [族 C] 流/事件 ioctl ==="
strace -f -e trace=ioctl -o $TRACE_DIR/03_stream_ops.log \
  python3 -c "
import ctypes
lib = ctypes.CDLL('libascendcl.so')
lib.aclInit(None)
lib.aclrtSetDevice(0)
stream = ctypes.c_void_p()
lib.aclrtCreateStream(ctypes.byref(stream))
lib.aclrtSynchronizeStream(stream)
lib.aclrtDestroyStream(stream)
lib.aclrtResetDevice(0)
lib.aclFinalize()
" 2>/dev/null || true

echo "=== [族 D] 模型推理 ioctl ==="
# 需要先有一个 .om 模型文件
if [ -f /tmp/test_model.om ]; then
  strace -f -e trace=ioctl -o $TRACE_DIR/04_model_infer.log \
    python3 -c "
import ctypes
lib = ctypes.CDLL('libascendcl.so')
lib.aclInit(None)
lib.aclrtSetDevice(0)
# 加载模型 → 推理 → 取结果（简化）
model_id = ctypes.c_int32()
lib.aclmdlLoadFromFile('/tmp/test_model.om', ctypes.byref(model_id))
# ... 推理逻辑 ...
lib.aclmdlUnload(model_id)
lib.aclrtResetDevice(0)
lib.aclFinalize()
" 2>/dev/null || true
fi

echo "=== [族 E] 模型转换 ioctl ==="
if [ -f /tmp/test_model.onnx ]; then
  strace -f -e trace=ioctl -o $TRACE_DIR/05_model_convert.log \
    atc --model=/tmp/test_model.onnx \
        --output=/tmp/test_converted \
        --soc_version=Ascend910B \
        --framework=5 2>/dev/null || true
fi

echo "=== 汇总去重 ==="
# 提取所有唯一的 ioctl 编号
cat $TRACE_DIR/*.log | \
  grep "ioctl(" | \
  awk '{print $NF}' | \
  sort -u > $TRACE_DIR/all_unique_ioctls.txt

echo "共捕获 $(wc -l < $TRACE_DIR/all_unique_ioctls.txt) 个不同的 ioctl 编号"
echo "详细结果在 $TRACE_DIR/ 目录下"

# 输出每个族命中了多少个
echo ""
echo "=== 各族命中统计 ==="
for f in $TRACE_DIR/*.log; do
  name=$(basename $f .log)
  count=$(grep -c "ioctl(" $f 2>/dev/null || echo 0)
  unique=$(grep "ioctl(" $f | awk '{print $NF}' | sort -u | wc -l)
  echo "  $name: 总调用 $count 次, 去重 $unique 个"
done
```

### 第六步：AI 辅助分析

抓完后把日志喂给 AI（Claude/GPT/Qoder），让它：

1. **归类**：把 ioctl 编号按功能分组（设备管理/内存/流/模型/...）
2. **推断结构体**：根据 `_IOC` 的 size 字段推断每个 ioctl 的参数结构
3. **标注安全等级**：
   - 只读查询类 → 安全（白名单）
   - 内存分配类 → 受限（需配额）
   - 固件升级/配置修改类 → 危险（黑名单）
4. **生成 C 结构体定义**：为阶段二写 proxy 做准备

```
AI 提示词模板：
"以下是昇腾 NPU 的 strace ioctl 抓取日志，请：
 1. 按功能归类每个 ioctl 编号
 2. 根据 size 字段推断参数结构体
 3. 标注安全等级（安全/受限/危险）
 4. 生成 C 语言结构体定义
 [粘贴日志]"
```

### 成本与时间

| 方案 | 时长 | 费用 | 覆盖率 |
|------|------|------|--------|
| 盲抓（不先看头文件） | 3-5 天 | ¥100-180 | 60-70% |
| **定向抓（先看头文件）** | **1-2 天** | **¥36-86** | **80-90%** |
| 定向抓 + AI 分析 | 1 天 | ¥36-86 | 80-90%（含归类） |

> 先看头文件 = 知道要抓什么 = 不浪费机时盲等 = 省钱省时

---

## 阶段一实际进展（截至 2026-10-24）

> 阶段一已基本完成。以下为实际执行结果和后续补全计划。

### 已完成工作

| 指标 | 数值 |
|------|------|
| 运行时确认（单卡+双卡合并） | **80 种** |
| 二进制独有（无法触发） | ~24 种 |
| **总 ioctl 目录** | **~104 种** |
| hisi_hdc 覆盖率 | 18/18 (100%) |
| davinci_manager 覆盖 | 59/~83 (71%) |
| 0x5a 族 | 运行时确认 ✅ |
| 0x89 族 | 仅二进制（双卡 PCIe 也不触发） |

### 关键发现：LD_PRELOAD 优于 strace

| 指标 | strace | LD_PRELOAD | 差异 |
|------|--------|-----------|------|
| 总调用次数 | 4332 | 5307 | +22% |
| 唯一签名数 | 48 | **71** | **+48%** |
| 0x4d 族 | 19 | 26 | +7 |
| 0x48 族 | 9 | 18 | +9 |
| 0x5a 族 | 0 | 2 | +2（首次确认） |

**结论**：strace 对昇腾 NPU 设备的 ioctl 解码存在严重遗漏（~33%），LD_PRELOAD 是更可靠的抓取手段。

### 抓取工具链

| 工具 | 路径 | 用途 |
|------|------|------|
| LD_PRELOAD hook | `/tmp/ioctl_log.c` → `/tmp/ioctl_log.so` | 用户态 ioctl 全拦截 |
| extract_npu_ioctl.py | `tools/extract_npu_ioctl.py` | strace 日志解析（v2） |
| ascend-ioctl-capture-all.sh | `tools/ascend-ioctl-capture-all.sh` | 7 族定向抓取脚本 |
| ioctl 目录文档 | `docs/ascend-ioctl-catalog.md` | 95 种 ioctl 完整目录 |

---

## 待补全计划

### 计划 A：0x89 族探查（需单机多卡）

> ✅ **已完成**（结果：双卡 HCCL 不触发 0x89，需 8 卡 HCCS 环境）

### 计划 B：0x4d 剩余探查

> ✅ **已完成**（双卡 HCCL 新增 10 种，剩余 24 种为固件路径不可达）

### 计划 C：/dev/devmm_svm 探查

> ⚠️ 未完成（需特殊权限环境，留作后续）

> 0x89 族 6 种 ioctl（nr=0x0b/0x0c/0x13/0x14/0x16/0x1c）仅二进制分析可见，运行时未触发。
> 推测为 HCCL 集合通信的设备发现/拓扑查询接口，需 ≥2 张 NPU 才能触发。

**环境需求**：单机 2 卡昇腾 910B（AutoDL/共绩/极智算均有）

**触发命令**：
```bash
LD_PRELOAD=/tmp/ioctl_log.so \
torchrun --nproc_per_node=2 --master_addr=127.0.0.1 --master_port=29500 -c "
import torch, torch_npu, torch.distributed as dist
dist.init_process_group(backend='hccl')
x = torch.randn(64, device=f'npu:{dist.get_rank()}')
dist.all_reduce(x)
dist.destroy_process_group()
" 2>/tmp/ioctl_2card.txt

grep "\[IOCTL\]" /tmp/ioctl_2card.txt | awk '{print $3, $4}' | sort -u
```

**预计新增**：0x89 族 6 种 → 总目录从 95 种提升到 ~101 种

### 计划 B：0x4d 剩余 17 种探查（更复杂负载）

> 0x4d 族仍有 17 种二进制独有 ioctl 未触发（nr=0x11/0x12/0x15/0x16/0x1d/0x1e/0x20/0x33/0x35/0x36/0x3f/0x4c/0x4d/0x51/0x56/0x5a/0x5b/0x5c/0x61/0x62/0x64/0x68/0x69/0x6a/0x74/0x76/0x94/0x9e/0x9f/0xa0/0xa3/0xaf/0xb9）。
> 可能需要更复杂的模型推理（Transformer/训练循环）或模型加载（.om 格式）才能触发。

**触发负载**：
```bash
LD_PRELOAD=/tmp/ioctl_log.so python3 -c "
import torch, torch_npu

# Transformer 层
model = torch.nn.TransformerEncoderLayer(
    d_model=512, nhead=8, dim_feedforward=2048, batch_first=True
).npu().eval()
x = torch.randn(4, 128, 512, device='npu:0')
y = model(x)

# 训练循环
model2 = torch.nn.Sequential(
    torch.nn.Linear(512, 256), torch.nn.ReLU(), torch.nn.Linear(256, 10)
).npu()
opt = torch.optim.AdamW(model2.parameters(), lr=1e-3)
for i in range(10):
    inp = torch.randn(32, 512, device='npu:0')
    target = torch.randint(0, 10, (32,), device='npu:0')
    loss = torch.nn.CrossEntropyLoss()(model2(inp), target)
    opt.zero_grad(); loss.backward(); opt.step()

# 模型保存/加载
torch.save(model2.state_dict(), '/tmp/model.pt')
model2.load_state_dict(torch.load('/tmp/model.pt'))

# 内存操作
torch.npu.empty_cache()
torch.npu.reset_peak_memory_stats()
print('DONE')
" 2>/tmp/ioctl_complex.txt

grep "\[IOCTL\]" /tmp/ioctl_complex.txt | awk '{print $3, $4}' | sort -u
```

### 计划 C：/dev/devmm_svm 探查（需权限）

> `/dev/devmm_svm` (502:0) 虚拟内存管理设备当前权限不足无法 open。
> 获取 root 或调整权限后，可能有新的 ioctl 编号。

```bash
# 检查权限
ls -la /dev/devmm_svm
# 尝试 open（需 root 或设备权限）
python3 -c "import os; fd = os.open('/dev/devmm_svm', os.O_RDWR); print(f'fd={fd}')"
```

### 优先级排序

| 优先级 | 计划 | 预计新增 | 难度 | 成本 |
|--------|------|---------|------|------|
| P1 | A: 0x89 族（单机 2 卡） | ~6 种 | 低 | ¥5-10/时 |
| P2 | B: 0x4d 剩余（复杂负载） | ~5-10 种 | 中 | 当前容器可跑 |
| P3 | C: devmm_svm（需权限） | 未知 | 高 | 需特殊环境 |

**建议**：先跑 P2（当前容器即可），再租 2 卡机跑 P1。P3 留作后续。
