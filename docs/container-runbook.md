# 容器上运行指南

> 在昇腾 910B 云实例上执行 ioctl 抓取的快速参考

## 环境准备

```bash
# 安装 strace（容器内通常没有）
apt-get update && apt-get install -y strace

# 确认 NPU 可用
npu-smi info
python3 -c "import torch, torch_npu; print('NPU:', torch.npu.is_available(), '设备数:', torch.npu.device_count())"

# 确认 CANN 版本
cat /usr/local/Ascend/driver/version.info
echo $ASCEND_HOME
```

## 快速抓取（单条命令）

```bash
# 基础抓取（矩阵乘法，覆盖初始化和核心命令）
strace -ff -e trace=openat,close,ioctl -o /tmp/trace_basic \
  python3 -c "
import torch, torch_npu
x = torch.randn(64, 64, device='npu:0')
y = x.mm(x)
torch.npu.synchronize()
print('DONE')
"

# 解析结果
python3 extract_npu_ioctl.py /tmp/trace_basic.*
```

## 完整抓取（全部 7 族）

```bash
# 上传工具到容器
scp tools/ascend-ioctl-capture-all.sh tools/extract_npu_ioctl.py root@<容器IP>:/workspace/

# 在容器内执行
cd /workspace
bash ascend-ioctl-capture-all.sh
```

## 各族触发说明

| 族 | 触发方式 | 预期 ioctl | 前置条件 |
|----|---------|-----------|---------|
| A 设备管理 | `torch.npu.is_available()` + `get_device_properties()` | 0x45, 0x55 | 无 |
| B 内存操作 | `aclrtMalloc/Free/Memcpy` (ctypes 调 libascendcl.so) | 0x4d RW 族 | 族 A 完成 |
| C 流/事件 | `aclrtCreateStream/Event` | 0x4d NONE 族 | 族 A 完成 |
| D 矩阵运算 | `torch.mm/relu/conv2d` 多种 size | 0x58 族（算子加载） | 族 A 完成 |
| E 模型推理 | `aclmdlLoadFromFile/Execute` | 0x4d + 0x58 密集 | 需 .om 模型文件 |
| F 多卡通信 | `dist.all_reduce/broadcast` (HCCL) | 0x89 族 | 需 ≥2 卡 |
| G 异常路径 | 超大分配/非法设备号/越界拷贝 | 散落各 magic | 族 A 完成 |

## 已知限制

- **单卡无法触发族 F**（多卡通信）：需要 8 卡整机环境
- **族 E 需要 .om 模型**：先用 `torch.onnx.export` 导出 ONNX，再用 `atc` 转换
- **0x5a/0x89 族触发条件未知**：可能在特定固件操作或底层调度时出现

## 抓取后分析

```bash
# 1. 提取所有 _IOC 签名
python3 extract_npu_ioctl.py /tmp/ascend_ioctl_traces/*.log.* > /tmp/ioctl_summary.txt

# 2. 与已有 catalog 对比
# 看新增了哪些 ioctl 编号
diff <(grep "_IOC" /tmp/old_summary.txt | sort -u) \
     <(grep "_IOC" /tmp/ioctl_summary.txt | sort -u)

# 3. 统计覆盖率
echo "已有: 84 种 (strace 46 + 二进制 38)"
echo "新增: $(grep "_IOC" /tmp/ioctl_summary.txt | sort -u | wc -l) 种"
```

## 省钱提示

| 操作 | 建议 |
|------|------|
| 编写脚本 | 在本地写好再上传，不要在云上写 |
| 调试 | 先跑族 A 确认 strace 正常，再跑全部 |
| 关机 | 每族跑完先 `kill strace`，确认数据保存后再关机 |
| 数据备份 | `scp /tmp/ascend_ioctl_traces/*.log.* 本地:/backup/` |
