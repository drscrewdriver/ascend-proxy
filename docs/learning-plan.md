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

### 阶段三：OCI Runtime 包装（第 6-7 周）

| 周 | 任务 | 产出 | AI 辅助 |
|----|------|------|---------|
| W6 | 学习 OCI runtime spec（读规范 + 看 runc 源码关键路径） | 理解 spec 结构 | AI 解读规范文档 |
| W6 | 写 `ascend-oci-runtime` wrapper（Go/Rust） | 能替代 runc 的空壳 | AI 生成 wrapper 代码 |
| W7 | 实现：修改 OCI spec，把 `/dev/davinci0` 替换为代理设备 | spec 修改逻辑 | AI 辅助 JSON 操作 |
| W7 | 实现：启动 proxy 进程 + 调用 runc | 完整 runtime | AI 调试进程管理 |
| W7 | 接入 containerd 测试（端到端：Pod 申请 → NPU 可见） | 可演示的 demo | — |

**阶段产出**：`ascend-oci-runtime` + containerd 集成验证截图

---

### 阶段四：沙箱集成（第 8-11 周，可选进阶）

| 周 | 任务 | 产出 | AI 辅助 |
|----|------|------|---------|
| W8-9 | 方案 A：fork gVisor，扩展 `--nvproxy` 思路支持 Ascend | gVisor fork + patch | AI 读 gVisor 源码 |
| W8-9 | 方案 B（更简单）：用 seccomp 白名单限制容器只能发 NPU ioctl | seccomp profile | AI 生成 seccomp 规则 |
| W10 | 安全测试：尝试在沙箱内发起危险 ioctl，验证被拦截 | 安全测试报告 | AI 生成攻击用例 |
| W10 | 性能测试：对比直通 vs 代理的延迟开销 | 性能对比数据 | AI 分析数据 |
| W11 | 整理文档 + 开源发布（GitHub + README + 架构图） | 开源项目 | AI 写文档 |

**阶段产出**：可开源的完整项目（GitHub 仓库）

---

## 里程碑总览

```
W1-W2   ████░░░░░░░░░░░░░░░░  阶段一：抓接口 → ioctl catalog
W3-W5   ░░░░██████░░░░░░░░░░  阶段二：最小代理 → proxy 二进制
W6-W7   ░░░░░░░░░░████░░░░░░  阶段三：OCI wrapper → 端到端 demo
W8-W11  ░░░░░░░░░░░░░░██████  阶段四：沙箱集成 → 开源项目（可选）
```

| 里程碑 | 时间 | 交付物 | 验证标准 |
|--------|------|--------|---------|
| M1 | W2 末 | `ascend-ioctl-catalog.md` | 至少列出 10 个 ioctl 及用途 |
| M2 | W5 末 | `ascend-ioctl-proxy` | 能代理 3 种以上 ioctl 并返回正确结果 |
| M3 | W7 末 | `ascend-oci-runtime` + demo | containerd 创建 Pod 能看到 NPU 设备 |
| M4 | W11 末 | GitHub 开源项目 | README + 架构图 + 安全/性能测试报告 |

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
