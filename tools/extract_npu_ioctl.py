#!/usr/bin/env python3
"""
extract_npu_ioctl.py - 从 strace 日志中提取昇腾 NPU ioctl

用法:
    # 1. 先用 strace 抓取（按 PID 分文件）
    strace -ff -e trace=openat,close,ioctl -o /tmp/trace_precise \
      python3 -c "import torch, torch_npu; x=torch.randn(64,64,device='npu:0'); y=x.mm(x)"

    # 2. 运行本脚本解析
    python3 extract_npu_ioctl.py /tmp/trace_precise.*

注意:
    - strace -ff 分文件后每行无 PID 前缀
    - strace 对未知设备的 ioctl 解码不可靠（MIXER_WRITE/ZFS_IOC 等均为误标）
    - 只有 _IOC(...) 格式的未解码项是真实 NPU ioctl
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
    fd_map = {}  # fd -> device_path
    ioctls = []  # list of (fd, ioctl_sig, arg, device)

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
            m = re.match(r'ioctl\((\d+),\s*(.+?)\s*,\s*(0x[0-9a-f]+)\)', line)
            if m:
                fd = int(m.group(1))
                sig = m.group(2).strip()
                arg = m.group(3)

                # 只处理 NPU 设备上的 ioctl
                if fd in fd_map:
                    device = fd_map[fd]
                    # 过滤噪声
                    if not is_noise(sig):
                        ioctls.append((fd, sig, arg, device))

    return ioctls


def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <trace_file> [trace_file2 ...]")
        print(f"      {sys.argv[0]} /tmp/trace_precise.*")
        sys.exit(1)

    # 收集所有 trace 文件
    files = []
    for pattern in sys.argv[1:]:
        files.extend(glob.glob(pattern))

    if not files:
        print("未找到 trace 文件")
        sys.exit(1)

    # 按设备归类统计
    device_ioctls = defaultdict(set)  # device -> set of ioctl signatures

    for logfile in sorted(files):
        ioctls = parse_trace_file(logfile)
        for fd, sig, arg, device in ioctls:
            device_ioctls[device].add(sig)

    # 输出结果
    print("=" * 60)
    print("昇腾 NPU ioctl 提取结果")
    print("=" * 60)

    for device in sorted(device_ioctls.keys()):
        ioctls = sorted(device_ioctls[device])
        print(f"\n=== {device} ({len(ioctls)} 种) ===")
        for sig in ioctls:
            print(f"  {sig}")

    # 统计汇总
    total = sum(len(v) for v in device_ioctls.values())
    print(f"\n{'=' * 60}")
    print(f"总计: {total} 种不同 ioctl")


if __name__ == '__main__':
    main()
