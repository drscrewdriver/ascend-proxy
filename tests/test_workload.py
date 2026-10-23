#!/usr/bin/env python3
"""
test_workload.py — 端到端验证 ascend-proxy

用法：
  # 终端 1：启动 supervisor
  sudo ./bin/ascend-proxy -v

  # 终端 2：跑容器负载（经 LD_PRELOAD 注入 seccomp）
  LD_PRELOAD=./bin/inject_seccomp.so python3 tests/test_workload.py

预期：
  - supervisor 日志显示每个 ioctl 被查询和转发
  - Python 脚本正常完成所有测试用例
  - 未 proxy 时能对齐 ioctl 数量
"""
import sys
import os

def check_env():
    """验证 proxy 环境变量正确设置"""
    if "ASCEND_PROXY_DISABLE" in os.environ:
        print("⚠️  ASCEND_PROXY_DISABLE=1 已设置，测试无实际代理")
        return False
    print("✅ 环境检查：inject_seccomp.so 应已加载")
    return True

def test_basic_init():
    """测试 1：torch_npu 初始化"""
    import torch, torch_npu
    assert torch.npu.is_available(), "NPU 不可用"
    assert torch.npu.device_count() >= 1, "无 NPU 设备"
    print(f"  torch={torch.__version__}, npu devices={torch.npu.device_count()}")
    print("✅ test_basic_init PASS")

def test_memory_alloc():
    """测试 2：内存分配触发 0x4d 族 ioctl"""
    import torch, torch_npu
    sizes = [64, 1024, 1024*1024, 4*1024*1024]
    for sz in sizes:
        t = torch.empty(sz, device='npu:0')
        del t
    torch.npu.synchronize()
    print(f"✅ test_memory_alloc PASS (n={len(sizes)} sizes)")

def test_matmul():
    """测试 3：矩阵乘法推理路径"""
    import torch, torch_npu
    x = torch.randn(64, 64, device='npu:0')
    y = torch.randn(64, 64, device='npu:0')
    z = x.mm(y)
    torch.npu.synchronize()
    assert z.shape == (64, 64)
    print("✅ test_matmul PASS")

def test_linear_forward():
    """测试 4：Linear 层前向推理（覆盖算子加载路径）"""
    import torch, torch_npu
    model = torch.nn.Linear(128, 64).npu().eval()
    x = torch.randn(32, 128, device='npu:0')
    with torch.no_grad():
        y = model(x)
    torch.npu.synchronize()
    assert y.shape == (32, 64)
    print(f"✅ test_linear_forward PASS (shape={tuple(y.shape)})")

def test_streams():
    """测试 5：多流路径"""
    import torch, torch_npu
    s1 = torch.npu.Stream()
    s2 = torch.npu.Stream()
    with torch.npu.stream(s1):
        a = torch.randn(100, device='npu:0')
    with torch.npu.stream(s2):
        b = torch.randn(100, device='npu:0')
    s2.wait_stream(s1)
    c = a + b
    torch.npu.synchronize()
    print("✅ test_streams PASS")

def test_error_paths():
    """测试 6：错误路径不 crash"""
    import torch, torch_npu
    # 尝试分配超大内存（应该失败但不 crash）
    try:
        t = torch.empty(60 * 1024**3, dtype=torch.uint8, device='npu:0')
        print("  ⚠️  分配 60GB 居然成功了？")
    except RuntimeError as e:
        print(f"  ✓ 分配 60GB 被拒绝: {str(e)[:60]}")
    torch.npu.synchronize()
    print("✅ test_error_paths PASS")

def main():
    print("=== ascend-proxy 端到端测试 ===\n")
    check_env()
    print()

    tests = [
        ("基础初始化", test_basic_init),
        ("内存分配", test_memory_alloc),
        ("矩阵乘法", test_matmul),
        ("Linear 推理", test_linear_forward),
        ("多流依赖", test_streams),
        ("异常路径", test_error_paths),
    ]

    passed, failed = 0, 0
    for name, fn in tests:
        print(f"--- {name} ---")
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"❌ {name} FAIL: {type(e).__name__}: {e}")
            failed += 1
        print()

    print(f"=== 结果: {passed} 通过 / {failed} 失败 ===")
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
