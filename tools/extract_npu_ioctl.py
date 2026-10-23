#!/usr/bin/env python3
"""
extract_npu_ioctl.py - 从 strace 日志中提取昇腾 NPU ioctl（v2）

用法:
    # 1. 先用 strace 抓取（按 PID 分文件）
    strace -ff -e trace=openat,close,ioctl -o /tmp/trace_precise \
      python3 -c "import torch, torch_npu; x=torch.randn(64,64,device='npu:0'); y=x.mm(x)"

    # 2. 运行本脚本解析
    python3 extract_npu_ioctl.py /tmp/trace_precise.*

    # 3. 与基线对比（看新增了什么）
    python3 extract_npu_ioctl.py /tmp/trace_B.* > /tmp/result_B.txt
    diff /tmp/result_A.txt /tmp/result_B.txt | grep "^>"

功能:
    - 按 PID 分文件解析（适配 strace -ff 格式）
    - 维护 fd_map，跟踪 openat/close 建立 fd→设备映射
    - 过滤噪声 ioctl（MIXER_WRITE/ZFS_IOC 等 strace 误标项）
    - 只保留 _IOC(...) 格式的真实 NPU ioctl
    - 输出时序信息（第一个 ioctl 通常是初始化握手）
    - 输出 arg 值（用于推断结构体大小）
"""

import re
import sys
import glob
from collections import defaultdict

# NPU 设备文件
NPU_DEVICES = {
    '/dev/davinci1',
    '/dev/davinci_manager',
    '/dev/devmm_svm',
    '/dev/hisi_hdc',
}

# 噪声 ioctl 前缀（strace 误标的系统 ioctl）
NOISE_PREFIXES = {
    'TCGETS', 'TCSETS', 'TCSETSW', 'TCSETSF',
    'TIOCGWINSZ', 'TIOCSWINSZ', 'TIOCGPGRP', 'TIOCSPGRP',
    'VT_GETMODE', 'VT_SETMODE',
    'FIONBIO', 'FIOCLEX', 'FIONCLEX',
    'ZFS_IOC_', 'USBDEVFS_', 'SNDRV_', 'MIXER_WRITE', 'SND_',
}


def is_noise(sig):
    """判断是否为噪声 ioctl"""
    return any(sig.startswith(p) for p in NOISE_PREFIXES)


def parse_trace_file(logfile):
    """解析单个 strace trace 文件"""
    fd_map = {}       # fd -> device_path
    ioctls = []       # list of (seq, fd, ioctl_sig, arg, device, ret)
    seq = 0           # 全局序号（用于时序分析）

    with open(logfile) as f:
        for line in f:
            # 匹配 openat: openat(AT_FDCWD, "/dev/davinci_manager", O_RDWR) = 3
            m = re.match(r'openat\([^,]+,\s*"([^"]+)"', line)
            if m:
                path = m.group(1)
                rm = re.search(r'= (\d+)', line)
                if rm and path in NPU_DEVICES:
                    fd = int(rm.group(1))
                    fd_map[fd] = path

            # 匹配 close: close(3) = 0
            m = re.match(r'close\((\d+)\)', line)
            if m:
                fd = int(m.group(1))
                fd_map.pop(fd, None)

            # 匹配 ioctl: ioctl(3, _IOC(...), 0x...) = 0
            # 注意：.+? 是非贪婪匹配，但会回溯到最后一个 , 0xhex) 模式
            m = re.match(r'ioctl\((\d+),\s*(.+?)\s*,\s*(0x[0-9a-f]+)\)\s*=\s*(-?\d+)', line)
            if m:
                fd = int(m.group(1))
                sig = m.group(2).strip()
                arg = m.group(3)
                ret = int(m.group(4))

                if fd in fd_map:
                    device = fd_map[fd]
                    if not is_noise(sig):
                        ioctls.append((seq, fd, sig, arg, device, ret))
                        seq += 1

    return ioctls


def decode_ioctl_signature(sig):
    """从 _IOC(dir, type, nr, size) 提取 magic 和 nr"""
    m = re.match(r'_IOC\([^,]+,\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+)', sig)
    if m:
        magic = int(m.group(1), 16)
        nr = int(m.group(2), 16)
        return f"magic=0x{magic:02x} nr=0x{nr:02x}"
    return sig


def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <trace_file> [trace_file2 ...]")
        print(f"      {sys.argv[0]} /tmp/trace_precise.*")
        sys.exit(1)

    # 收集所有 trace 文件
    files = []
    for pattern in sys.argv[1:]:
        files.extend(sorted(glob.glob(pattern)))

    if not files:
        print("未找到 trace 文件")
        sys.exit(1)

    # 按设备归类
    device_ioctls = defaultdict(list)   # device -> [(seq, sig, arg, ret)]
    device_unique = defaultdict(set)    # device -> set of sigs

    for logfile in files:
        ioctls = parse_trace_file(logfile)
        for seq, fd, sig, arg, device, ret in ioctls:
            device_ioctls[device].append((seq, sig, arg, ret))
            device_unique[device].add(sig)

    # ============================================================
    # 输出 1：按设备的唯一 ioctl 列表
    # ============================================================
    print("=" * 70)
    print("昇腾 NPU ioctl 提取结果 (v2)")
    print("=" * 70)

    for device in sorted(device_unique.keys()):
        sigs = sorted(device_unique[device])
        print(f"\n=== {device} ({len(sigs)} 种) ===")
        for sig in sigs:
            decoded = decode_ioctl_signature(sig)
            print(f"  {sig}")
            if decoded != sig:
                print(f"    → {decoded}")

    # ============================================================
    # 输出 2：时序分析（每个设备的第一个 ioctl）
    # ============================================================
    print(f"\n{'=' * 70}")
    print("时序分析（每个设备上最早出现的 ioctl）")
    print("=" * 70)

    for device in sorted(device_ioctls.keys()):
        entries = device_ioctls[device]
        if not entries:
            continue
        print(f"\n--- {device} ---")
        # 显示前 10 条（时序）
        for i, (seq, sig, arg, ret) in enumerate(entries[:10]):
            decoded = decode_ioctl_signature(sig)
            status = "✓" if ret == 0 else f"✗({ret})"
            print(f"  [{seq:4d}] {decoded:40s} arg={arg} {status}")
        if len(entries) > 10:
            print(f"  ... 共 {len(entries)} 条")

    # ============================================================
    # 输出 3：统计汇总
    # ============================================================
    total_unique = sum(len(v) for v in device_unique.values())
    total_calls = sum(len(v) for v in device_ioctls.values())
    print(f"\n{'=' * 70}")
    print(f"总计: {total_unique} 种不同 ioctl, {total_calls} 次调用")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
