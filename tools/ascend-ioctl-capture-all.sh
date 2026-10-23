#!/bin/bash
# ascend-ioctl-capture-all.sh - 按族定向抓取昇腾 NPU ioctl
# 在 CANN 9.1.0 / 910B2 容器上运行
# 用法: bash ascend-ioctl-capture-all.sh

set -e
TRACE_DIR="/tmp/ascend_ioctl_traces"
rm -rf $TRACE_DIR
mkdir -p $TRACE_DIR

echo "============================================================"
echo "  昇腾 NPU ioctl 定向抓取"
echo "  环境: CANN $(cat /usr/local/Ascend/driver/version.info 2>/dev/null || echo 'unknown')"
echo "============================================================"

# 确保 strace 可用
if ! command -v strace &>/dev/null; then
    echo "[!] strace 未安装，正在安装..."
    apt-get update -qq && apt-get install -y -qq strace
fi

# ============================================================
# 族 A: 设备初始化与状态查询
# ============================================================
echo ""
echo "=== [族 A] 设备初始化与状态查询 ==="

strace -ff -e trace=openat,close,ioctl -o $TRACE_DIR/01_init.log \
  python3 -c "
import torch, torch_npu
print('is_available:', torch.npu.is_available())
print('device_count:', torch.npu.device_count())
print('current_device:', torch.npu.current_device())
# 获取设备属性
props = torch.npu.get_device_properties(0)
print('device_name:', props.name)
print('total_memory:', props.total_memory)
" 2>/dev/null || true

echo "  完成: $(grep -c ioctl $TRACE_DIR/01_init.log.* 2>/dev/null | tail -1 | cut -d: -f2) 条 ioctl"

# ============================================================
# 族 B: ACL 内存操作
# ============================================================
echo ""
echo "=== [族 B] ACL 内存操作 ==="

strace -ff -e trace=openat,close,ioctl -o $TRACE_DIR/02_memory.log \
  python3 -c "
import ctypes, os

# 加载 ACL 库
acl = ctypes.CDLL('libascendcl.so')

# 初始化
acl.aclInit(None)
acl.aclrtSetDevice(0)

# 内存分配（多种大小）
sizes = [64, 256, 1024, 4096, 1024*1024, 4*1024*1024]
bufs = []
for s in sizes:
    buf = ctypes.c_void_p()
    ret = acl.aclrtMalloc(ctypes.byref(buf), s, 0)  # ACL_MEM_MALLOC_HUGE_FIRST
    print(f'aclrtMalloc({s}) = {buf.value}, ret={ret}')
    bufs.append(buf)

# Host→Device 拷贝
import struct
host_buf = (ctypes.c_uint8 * 1024)(*range(256)) * 4
ret = acl.aclrtMemcpy(bufs[2], host_buf, 1024, 3)  # ACL_MEMCPY_HOST_TO_DEVICE
print(f'aclrtMemcpy H2D = {ret}')

# Device→Host 拷贝
out_buf = (ctypes.c_uint8 * 1024)()
ret = acl.aclrtMemcpy(out_buf, 1024, bufs[2], 1024, 2)  # ACL_MEMCPY_DEVICE_TO_HOST
print(f'aclrtMemcpy D2H = {ret}')

# Device→Device 拷贝
ret = acl.aclrtMemcpy(bufs[3], 1024, bufs[2], 1024, 1)  # ACL_MEMCPY_DEVICE_TO_DEVICE
print(f'aclrtMemcpy D2D = {ret}')

# 内存释放
for buf in bufs:
    acl.aclrtFree(buf)
    print(f'aclrtFree({buf.value})')

# 清理
acl.aclrtResetDevice(0)
acl.aclFinalize()
print('DONE')
" 2>/dev/null || true

echo "  完成: $(grep -c ioctl $TRACE_DIR/02_memory.log.* 2>/dev/null | tail -1 | cut -d: -f2) 条 ioctl"

# ============================================================
# 族 C: 流与事件操作
# ============================================================
echo ""
echo "=== [族 C] 流与事件操作 ==="

strace -ff -e trace=openat,close,ioctl -o $TRACE_DIR/03_stream.log \
  python3 -c "
import ctypes

acl = ctypes.CDLL('libascendcl.so')
acl.aclInit(None)
acl.aclrtSetDevice(0)

# 创建多个流
streams = []
for i in range(4):
    s = ctypes.c_void_p()
    ret = acl.aclrtCreateStream(ctypes.byref(s))
    print(f'aclrtCreateStream[{i}] = {s.value}, ret={ret}')
    streams.append(s)

# 流同步
for s in streams:
    ret = acl.aclrtSynchronizeStream(s)
    print(f'aclrtSynchronizeStream({s.value}) = {ret}')

# 创建事件
events = []
for i in range(4):
    e = ctypes.c_void_p()
    ret = acl.aclrtCreateEvent(ctypes.byref(e))
    print(f'aclrtCreateEvent[{i}] = {e.value}, ret={ret}')
    events.append(e)

# 事件记录与查询
for i, e in enumerate(events):
    acl.aclrtRecordEvent(e, streams[i])
    ret = acl.aclrtQueryEventStatus(e)
    print(f'aclrtQueryEventStatus[{i}] = {ret}')

# 事件同步
for e in events:
    ret = acl.aclrtSynchronizeEvent(e, 5000)  # 5s timeout
    print(f'aclrtSynchronizeEvent = {ret}')

# 销毁
for e in events:
    acl.aclrtDestroyEvent(e)
for s in streams:
    acl.aclrtDestroyStream(s)

acl.aclrtResetDevice(0)
acl.aclFinalize()
print('DONE')
" 2>/dev/null || true

echo "  完成: $(grep -c ioctl $TRACE_DIR/03_stream.log.* 2>/dev/null | tail -1 | cut -d: -f2) 条 ioctl"

# ============================================================
# 族 D: 矩阵运算（触发算子内核加载）
# ============================================================
echo ""
echo "=== [族 D] 矩阵运算 ==="

strace -ff -e trace=openat,close,ioctl -o $TRACE_DIR/04_compute.log \
  python3 -c "
import torch, torch_npu

# 多种矩阵大小（触发不同算子内核）
for size in [16, 64, 256, 1024]:
    x = torch.randn(size, size, device='npu:0')
    y = x.mm(x)
    torch.npu.synchronize()
    print(f'mm({size}x{size}) done, result shape: {y.shape}')

# 多种算子
x = torch.randn(128, 128, device='npu:0')
print('relu:', torch.relu(x).shape)
print('sigmoid:', torch.sigmoid(x).shape)
print('softmax:', torch.softmax(x, dim=1).shape)
print('layer_norm:', torch.layer_norm(x, [128]).shape)
print('conv2d:', torch.nn.functional.conv2d(
    torch.randn(1, 3, 32, 32, device='npu:0'),
    torch.randn(16, 3, 3, 3, device='npu:0')
).shape)
torch.npu.synchronize()
print('DONE')
" 2>/dev/null || true

echo "  完成: $(grep -c ioctl $TRACE_DIR/04_compute.log.* 2>/dev/null | tail -1 | cut -d: -f2) 条 ioctl"

# ============================================================
# 族 E: 模型加载与推理（如果有 .om 模型）
# ============================================================
echo ""
echo "=== [族 E] 模型加载与推理 ==="

# 先用 torch_npu 导出一个简单模型
python3 -c "
import torch, torch_npu

class SimpleModel(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = torch.nn.Linear(128, 64)
        self.relu = torch.nn.ReLU()
    def forward(self, x):
        return self.relu(self.linear(x))

model = SimpleModel().npu().eval()
dummy = torch.randn(1, 128, device='npu:0')
# 尝试 torch 导出
try:
    torch.onnx.export(model, dummy, '/tmp/simple_model.onnx',
                      input_names=['input'], output_names=['output'])
    print('ONNX exported to /tmp/simple_model.onnx')
except Exception as e:
    print(f'ONNX export failed: {e}')
" 2>/dev/null || true

# 如果有 atc 工具，转换为 .om
if command -v atc &>/dev/null && [ -f /tmp/simple_model.onnx ]; then
    atc --model=/tmp/simple_model.onnx \
        --output=/tmp/simple_model \
        --soc_version=Ascend910B2 \
        --framework=5 2>/dev/null || true
fi

# 用 ACL C API 加载推理
if [ -f /tmp/simple_model.om ]; then
    strace -ff -e trace=openat,close,ioctl -o $TRACE_DIR/05_infer.log \
      python3 -c "
import ctypes

acl = ctypes.CDLL('libascendcl.so')
acl.aclInit(None)
acl.aclrtSetDevice(0)

# 加载模型
model_id = ctypes.c_int32()
ret = acl.aclmdlLoadFromFile(b'/tmp/simple_model.om', ctypes.byref(model_id))
print(f'aclmdlLoadFromFile = {ret}, model_id={model_id.value}')

# 获取模型描述
desc = ctypes.c_void_p()
ret = acl.aclmdlGetDesc(ctypes.byref(desc), model_id)
print(f'aclmdlGetDesc = {ret}')

# 创建数据集（输入/输出 buffer）
input_data = ctypes.c_void_p()
ret = acl.aclCreateDataset(ctypes.byref(input_data))
print(f'aclCreateDataset = {ret}')

# 推理
output_data = ctypes.c_void_p()
ret = acl.aclmdlExecute(model_id, input_data, ctypes.byref(output_data))
print(f'aclmdlExecute = {ret}')

# 清理
acl.aclmdlDestroyDataset(input_data)
acl.aclmdlDestroyDataset(output_data)
acl.aclmdlUnload(model_id)
acl.aclrtResetDevice(0)
acl.aclFinalize()
print('DONE')
" 2>/dev/null || true
    echo "  完成: $(grep -c ioctl $TRACE_DIR/05_infer.log.* 2>/dev/null | tail -1 | cut -d: -f2) 条 ioctl"
else
    echo "  跳过（无 .om 模型文件）"
fi

# ============================================================
# 族 F: 多卡通信（HCCL）— 需要多卡环境
# ============================================================
echo ""
echo "=== [族 F] 多卡通信 (HCCL) ==="

DEVICE_COUNT=$(python3 -c "import torch, torch_npu; print(torch.npu.device_count())" 2>/dev/null || echo "0")

if [ "$DEVICE_COUNT" -ge 2 ]; then
    strace -ff -e trace=openat,close,ioctl -o $TRACE_DIR/06_hccl.log \
      python3 -c "
import torch, torch_npu
import torch.distributed as dist
import os

os.environ['MASTER_ADDR'] = '127.0.0.1'
os.environ['MASTER_PORT'] = '29500'
os.environ['RANK'] = '0'
os.environ['WORLD_SIZE'] = str($DEVICE_COUNT)

dist.init_process_group(backend='hccl')

# AllReduce
x = torch.randn(1024, device='npu:0')
dist.all_reduce(x)
print(f'all_reduce done, sum={x.sum().item():.4f}')

# Broadcast
dist.broadcast(x, src=0)
print(f'broadcast done')

# AllGather
tensors = [torch.zeros(1024, device='npu:0') for _ in range($DEVICE_COUNT)]
dist.all_gather(tensors, x)
print(f'all_gather done, got {len(tensors)} tensors')

dist.destroy_process_group()
print('DONE')
" 2>/dev/null || true
    echo "  完成: $(grep -c ioctl $TRACE_DIR/06_hccl.log.* 2>/dev/null | tail -1 | cut -d: -f2) 条 ioctl"
else
    echo "  跳过（设备数=$DEVICE_COUNT，需 ≥2 卡）"
fi

# ============================================================
# 族 G: 异常路径
# ============================================================
echo ""
echo "=== [族 G] 异常路径 ==="

strace -ff -e trace=openat,close,ioctl -o $TRACE_DIR/07_error.log \
  python3 -c "
import ctypes

acl = ctypes.CDLL('libascendcl.so')
acl.aclInit(None)
acl.aclrtSetDevice(0)

# 1. 分配超大内存（可能 OOM）
big = ctypes.c_void_p()
ret = acl.aclrtMalloc(ctypes.byref(big), 60*1024*1024*1024, 0)  # 60GB
print(f'aclrtMalloc(60GB) = {ret}')

# 2. 释放空指针
ret = acl.aclrtFree(ctypes.c_void_p(0))
print(f'aclrtFree(NULL) = {ret}')

# 3. 非法设备号
ret = acl.aclrtSetDevice(99)
print(f'aclrtSetDevice(99) = {ret}')

# 4. 拷贝越界
buf = ctypes.c_void_p()
acl.aclrtMalloc(ctypes.byref(buf), 64, 0)
host = (ctypes.c_uint8 * 256)()
ret = acl.aclrtMemcpy(buf, host, 256, 3)  # 源 256B > 目标 64B
print(f'aclrtMemcpy overflow = {ret}')
acl.aclrtFree(buf)

acl.aclrtResetDevice(0)
acl.aclFinalize()
print('DONE')
" 2>/dev/null || true

echo "  完成: $(grep -c ioctl $TRACE_DIR/07_error.log.* 2>/dev/null | tail -1 | cut -d: -f2) 条 ioctl"

# ============================================================
# 汇总
# ============================================================
echo ""
echo "============================================================"
echo "  汇总"
echo "============================================================"

# 合并所有 trace 并去重
ALL_IOCTLS=$(mktemp)
for f in $TRACE_DIR/*.log.*; do
    grep "_IOC" "$f" 2>/dev/null >> $ALL_IOCTLS || true
done

UNIQUE=$(sort -u $ALL_IOCTLS | wc -l)
echo ""
echo "总 ioctl 调用次数: $(wc -l < $ALL_IOCTLS)"
echo "去重后 ioctl 种类: $UNIQUE"
echo ""

# 按族统计
echo "各族命中:"
for f in $TRACE_DIR/*.log.*; do
    name=$(basename "$f" | sed 's/\.log\..*//')
    count=$(grep -c "_IOC" "$f" 2>/dev/null || echo 0)
    unique=$(grep "_IOC" "$f" 2>/dev/null | sort -u | wc -l)
    echo "  $name: $count 次调用, $unique 种"
done

echo ""
echo "详细 trace 文件在: $TRACE_DIR/"
echo ""
echo "下一步: 把 trace 文件用 extract_npu_ioctl.py 解析"
echo "  python3 extract_npu_ioctl.py $TRACE_DIR/*.log.*"
