/*
 * whitelist.c — 昇腾 NPU ioctl 白名单表
 *
 * 从 docs/ascend-ioctl-catalog.md 抄录。按 magic 分组，同 magic 内按 nr 升序，
 * 供二分查找使用。所有"运行时确认"条目 ALLOW；"二进制独有"条目 DENY。
 */
#include <stddef.h>
#include "whitelist.h"

/* 简化宏：dir_ 参数避免与结构体 designator .dir 同名导致预处理器误替换 */
#define E(mgc, nr_, dr_, sz_, act_, sec_, desc_) \
    { .magic = (mgc), .nr = (nr_), .dir = (dr_), .size = (sz_), \
      .action = (act_), .sec = (sec_), .desc = (desc_) }

#define A   PROXY_ALLOW
#define X   PROXY_DENY
#define U   PROXY_AUDIT

#define SAFE  SEC_SAFE
#define RST   SEC_RESTRICTED
#define DGR   SEC_DANGEROUS
#define UNK   SEC_UNKNOWN

const struct whitelist_entry ASCEND_WHITELIST[] = {
    /* ===== Magic 0x45 — 初始化/解锁族（2 种） ===== */
    E(0x45, 0x00, 0, 0,    A, SAFE, "设备探测"),
    E(0x45, 0x17, 0, 0,    A, SAFE, "解锁 ioctl（时序第 9 位）"),

    /* ===== Magic 0x4d NONE 方向（8 种，size=0） ===== */
    E(0x4d, 0x03, 0, 0,    A, SAFE, "设备初始化"),
    E(0x4d, 0x14, 0, 0,    A, SAFE, "资源查询"),
    E(0x4d, 0x3a, 0, 0,    A, SAFE, "设备属性查询"),
    E(0x4d, 0x3b, 0, 0,    A, SAFE, "设备状态查询"),
    E(0x4d, 0x6c, 0, 0,    A, SAFE, "设备同步"),
    E(0x4d, 0x70, 0, 0,    A, SAFE, "设备能力查询"),
    E(0x4d, 0x9a, 0, 0,    A, SAFE, "设备管理命令"),
    E(0x4d, 0xb6, 0, 0,    A, RST,  "资源释放"),

    /* ===== Magic 0x4d WRITE 方向（7 种，size=0x158） ===== */
    E(0x4d, 0x03, 1, 0x158, A, SAFE, "设备初始化（带参数）"),
    E(0x4d, 0x0c, 1, 0x158, A, UNK,  "LD 新发现 WRITE"),
    E(0x4d, 0x0d, 1, 0x158, A, UNK,  "LD 新发现 WRITE"),
    E(0x4d, 0x24, 1, 0x158, A, UNK,  "LD 新发现 WRITE"),
    E(0x4d, 0x2a, 1, 0x158, A, UNK,  "LD 新发现 WRITE"),
    E(0x4d, 0x3d, 1, 0x158, A, UNK,  "LD 新发现 WRITE"),
    E(0x4d, 0x40, 1, 0x158, A, UNK,  "LD 新发现 WRITE"),

    /* ===== Magic 0x4d RW 方向（11 种，size=0x158） ===== */
    E(0x4d, 0x05, 3, 0x158, A, SAFE, "设备信息查询"),
    E(0x4d, 0x0b, 3, 0x158, A, RST,  "上下文参数读写"),
    E(0x4d, 0x0f, 3, 0x158, A, SAFE, "资源状态查询"),
    E(0x4d, 0x11, 3, 0x158, A, RST,  "配置参数读写"),
    E(0x4d, 0x1a, 3, 0x158, A, RST,  "流/事件参数"),
    E(0x4d, 0x23, 3, 0x158, A, DGR,  "内存映射参数"),
    E(0x4d, 0x27, 3, 0x158, A, UNK,  "LD 新发现 RW"),
    E(0x4d, 0x2d, 3, 0x158, A, RST,  "模型加载参数"),
    E(0x4d, 0x2e, 3, 0x158, A, RST,  "推理执行参数"),
    E(0x4d, 0x31, 3, 0x158, A, SAFE, "结果查询"),
    E(0x4d, 0x43, 3, 0x158, A, UNK,  "未知 RW"),

    /* ===== Magic 0x4d HCCL 双卡新增（10 种） ===== */
    E(0x4d, 0x04, 0, 0,    A, UNK,  "多卡资源分配 (HCCL)"),
    E(0x4d, 0x0e, 0, 0,    A, UNK,  "设备配对命令 (HCCL)"),
    E(0x4d, 0x15, 0, 0,    A, UNK,  "多卡同步 (HCCL)"),
    E(0x4d, 0x16, 0, 0,    A, UNK,  "多卡通信参数 (HCCL)"),
    E(0x4d, 0x1b, 0, 0,    A, UNK,  "跨设备通信 (HCCL)"),
    E(0x4d, 0x1c, 0, 0,    A, UNK,  "跨设备同步 (HCCL)"),
    E(0x4d, 0x1d, 0, 0,    A, UNK,  "多卡链路查询 (HCCL)"),
    E(0x4d, 0x20, 0, 0,    A, UNK,  "多卡状态查询 (HCCL)"),
    E(0x4d, 0x6f, 0, 0,    A, UNK,  "多卡内存映射 (HCCL)"),
    E(0x4d, 0x71, 0, 0,    A, UNK,  "设备间链路状态 (HCCL)"),

    /* ===== Magic 0x4d 反向传播/优化器（1 种，P2 复杂负载新增） ===== */
    E(0x4d, 0x2f, 3, 0x158, A, UNK,  "反向传播/优化器 (torch_npu 训练)"),

    /* ===== Magic 0x55 — 设备能力族（3 种） ===== */
    E(0x55, 0x00, 2, 0x14,  A, SAFE, "读设备能力（全局第一个 ioctl）"),
    E(0x55, 0x01, 1, 0x04,  A, RST,  "设置设备模式"),
    E(0x55, 0x02, 3, 0x10,  A, RST,  "设备能力读写"),

    /* ===== Magic 0x57 — 配置查询族（6 种，全 RW size=0x08） ===== */
    E(0x57, 0x01, 3, 0x08,  A, SAFE, "配置参数读"),
    E(0x57, 0x04, 3, 0x08,  A, SAFE, "配置参数读"),
    E(0x57, 0x07, 3, 0x08,  A, SAFE, "配置参数读"),
    E(0x57, 0x08, 3, 0x08,  A, SAFE, "配置参数读"),
    E(0x57, 0x09, 3, 0x08,  A, SAFE, "配置参数读"),
    E(0x57, 0x0c, 3, 0x08,  A, SAFE, "配置参数读"),

    /* ===== Magic 0x58 — 设备操作族（15 种） ===== */
    E(0x58, 0x00, 3, 0x1c,  A, SAFE, "设备属性查询"),
    E(0x58, 0x01, 1, 0x1c,  A, RST,  "设备属性设置"),
    E(0x58, 0x04, 3, 0x1c,  A, SAFE, "算子参数查询"),
    E(0x58, 0x05, 3, 0x1c,  A, RST,  "平台参数读写"),
    E(0x58, 0x06, 3, 0x1c,  A, SAFE, "算子参数查询"),
    E(0x58, 0x08, 0, 0,     A, UNK,  "多卡配置查询 (HCCL)"),
    E(0x58, 0x0a, 1, 0x1c,  A, UNK,  "属性设置"),
    E(0x58, 0x0b, 3, 0x04,  A, SAFE, "开关量查询"),
    E(0x58, 0x0c, 3, 0x08,  A, SAFE, "计数器查询"),
    E(0x58, 0x0d, 3, 0x108, A, DGR,  "大数据块传输"),
    E(0x58, 0x0f, 3, 0x5c,  A, RST,  "配置块读写"),
    E(0x58, 0x10, 1, 0x34,  A, UNK,  "扩展写入"),
    E(0x58, 0x11, 1, 0x34,  A, UNK,  "扩展写入"),
    E(0x58, 0x12, 3, 0x34,  A, UNK,  "扩展读写"),
    E(0x58, 0x14, 3, 0x48,  A, UNK,  "扩展读写"),

    /* ===== Magic 0x5a — 扩展命令族（2 种） ===== */
    E(0x5a, 0x00, 0, 0,     A, UNK,  "扩展功能入口"),
    E(0x5a, 0x01, 0, 0,     A, UNK,  "扩展功能入口"),

    /* ===== Magic 0x48 — hisi_hdc 通道（17 种，全 NONE size=0） ===== */
    E(0x48, 0x07, 0, 0,     A, SAFE, "HDC 通道初始化"),
    E(0x48, 0x08, 0, 0,     A, SAFE, "HDC 通道配置"),
    E(0x48, 0x09, 0, 0,     A, UNK,  "HDC 命令"),
    E(0x48, 0x10, 0, 0,     A, RST,  "HDC 数据传输准备"),
    E(0x48, 0x11, 0, 0,     A, UNK,  "HDC 命令"),
    E(0x48, 0x13, 0, 0,     A, SAFE, "HDC 状态查询"),
    E(0x48, 0x14, 0, 0,     A, UNK,  "HDC 命令"),
    E(0x48, 0x15, 0, 0,     A, UNK,  "HDC 命令"),
    E(0x48, 0x16, 0, 0,     A, UNK,  "HDC 命令"),
    E(0x48, 0x17, 0, 0,     A, RST,  "HDC 数据传输"),
    E(0x48, 0x18, 0, 0,     A, SAFE, "HDC 完成确认"),
    E(0x48, 0x1a, 0, 0,     A, UNK,  "HDC 命令"),
    E(0x48, 0x1d, 0, 0,     A, SAFE, "HDC 通道关闭"),
    E(0x48, 0x40, 0, 0,     A, UNK,  "HDC 扩展命令"),
    E(0x48, 0x41, 0, 0,     A, UNK,  "HDC 扩展命令"),
    E(0x48, 0x42, 0, 0,     A, UNK,  "HDC 扩展命令"),
    E(0x48, 0x43, 0, 0,     A, UNK,  "HDC 扩展命令"),

    /* ===== Magic 0x89 — 未知族（6 种，仅二进制，双卡不触发）→ DENY ===== */
    E(0x89, 0x0b, 0, 0,     X, UNK,  "未知 (8 卡 HCCS 才触发)"),
    E(0x89, 0x0c, 0, 0,     X, UNK,  "未知 (8 卡 HCCS 才触发)"),
    E(0x89, 0x13, 0, 0,     X, UNK,  "未知 (8 卡 HCCS 才触发)"),
    E(0x89, 0x14, 0, 0,     X, UNK,  "未知 (8 卡 HCCS 才触发)"),
    E(0x89, 0x16, 0, 0,     X, UNK,  "未知 (8 卡 HCCS 才触发)"),
    E(0x89, 0x1c, 0, 0,     X, UNK,  "未知 (8 卡 HCCS 才触发)"),

    /* ===== Magic 0x4d 二进制独有（用户态不可达）→ DENY ===== */
    E(0x4d, 0x12, 0, 0,     X, UNK,  "上下文查询 (仅二进制可见)"),
    E(0x4d, 0x1e, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x33, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x35, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x36, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x3f, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x4c, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x4d, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x51, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x56, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x5a, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x5b, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x5c, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x61, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x62, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x64, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x68, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x69, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x6a, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x74, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x76, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x94, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x9e, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0x9f, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0xa0, 0, 0,     X, UNK,  "仅二进制可见"),
    E(0x4d, 0xa3, 0, 0,     X, RST,  "资源分配 (仅二进制可见)"),
    E(0x4d, 0xaf, 0, 0,     X, RST,  "仅二进制可见"),
    E(0x4d, 0xb9, 0, 0,     X, UNK,  "仅二进制可见"),
};

const size_t ASCEND_WHITELIST_LEN =
    sizeof(ASCEND_WHITELIST) / sizeof(ASCEND_WHITELIST[0]);

/* ============================================================
 * 查询实现：magic + nr 匹配（dir/size 不参与）
 *
 * 线性查找：同 magic+nr 可能有多个 dir 条目（如 0x4d nr=0x03 有 NONE 和 WRITE），
 * 取首个匹配。表总量 <110 条，一次查找 <100ns，相比 seccomp 通知的 ~10μs 可忽略。
 * ============================================================ */
const struct whitelist_entry *whitelist_lookup(uint32_t ioctl_req) {
    uint8_t magic = _IOC_TYPE(ioctl_req);
    uint8_t nr    = _IOC_NR(ioctl_req);

    for (size_t i = 0; i < ASCEND_WHITELIST_LEN; i++) {
        if (ASCEND_WHITELIST[i].magic == magic &&
            ASCEND_WHITELIST[i].nr    == nr) {
            return &ASCEND_WHITELIST[i];
        }
    }
    return NULL;
}
