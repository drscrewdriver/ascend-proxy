/*
 * common.h — ascend-proxy 公共定义
 *
 * 阶段一收集的 ioctl 编码常量、签名宏、安全等级枚举。
 * 所有值来自 docs/ascend-ioctl-catalog.md 实测数据。
 */
#ifndef ASCEND_PROXY_COMMON_H
#define ASCEND_PROXY_COMMON_H

#include <stdint.h>
#include <linux/ioctl.h>
#include <linux/seccomp.h>

/* ============================================================
 * 昇腾 NPU ioctl magic 号（阶段一实测）
 * ============================================================ */
#define ASCEND_MAGIC_INIT       0x45  /* 初始化/解锁族 */
#define ASCEND_MAGIC_CORE       0x4d  /* 核心命令族（最密集） */
#define ASCEND_MAGIC_CAPS       0x55  /* 设备能力族 */
#define ASCEND_MAGIC_CONFIG     0x57  /* 配置查询族 */
#define ASCEND_MAGIC_DEVOP      0x58  /* 设备操作族 */
#define ASCEND_MAGIC_EXT        0x5a  /* 扩展命令族 */
#define ASCEND_MAGIC_HDC        0x48  /* hisi_hdc 通道 */
#define ASCEND_MAGIC_UNKNOWN    0x89  /* 未知族（需 8 卡 HCCS） */

/* 判断一个 ioctl 编号是否属于昇腾 NPU */
#define ASCEND_IS_NPU_IOCTL(cmd) \
    (((cmd >> 8) & 0xFF) == ASCEND_MAGIC_INIT  || \
     ((cmd >> 8) & 0xFF) == ASCEND_MAGIC_CORE  || \
     ((cmd >> 8) & 0xFF) == ASCEND_MAGIC_CAPS  || \
     ((cmd >> 8) & 0xFF) == ASCEND_MAGIC_CONFIG || \
     ((cmd >> 8) & 0xFF) == ASCEND_MAGIC_DEVOP || \
     ((cmd >> 8) & 0xFF) == ASCEND_MAGIC_EXT   || \
     ((cmd >> 8) & 0xFF) == ASCEND_MAGIC_HDC   || \
     ((cmd >> 8) & 0xFF) == ASCEND_MAGIC_UNKNOWN)

/* ============================================================
 * 白名单查询结果
 * ============================================================ */
typedef enum {
    PROXY_ALLOW = 0,   /* 转发到真实设备 */
    PROXY_DENY  = 1,   /* 拒绝，返回 EPERM */
    PROXY_AUDIT = 2,   /* 记录日志但放行（观测期） */
} proxy_action_t;

/* 安全等级（对齐 catalog 分类） */
typedef enum {
    SEC_SAFE       = 0,
    SEC_RESTRICTED = 1,
    SEC_DANGEROUS  = 2,
    SEC_UNKNOWN    = 3,
} sec_level_t;

/* ============================================================
 * ioctl 签名（4 字节紧凑编码）
 * ============================================================ */
struct ioctl_sig {
    uint8_t  dir;    /* _IOC_DIR 结果: NONE=0, WRITE=1, READ=2, RW=3 */
    uint8_t  magic;
    uint8_t  nr;
    uint16_t size;   /* _IOC_SIZE 结果 */
} __attribute__((packed));

static inline uint32_t sig_from_req(uint32_t req) {
    /* 用一个 uint32 表示: dir[2b] | magic[8b] | nr[8b] | size[14b] */
    uint32_t dir   = _IOC_DIR(req);
    uint32_t type  = _IOC_TYPE(req);
    uint32_t nr    = _IOC_NR(req);
    uint32_t size  = _IOC_SIZE(req);
    return (dir << 30) | (size << 16) | (type << 8) | nr;
}

/* ============================================================
 * 设备路由（magic → 真实设备路径）
 * ============================================================ */
#define DEV_DAVINCI_MGR   "/dev/davinci_manager"
#define DEV_HDC           "/dev/hisi_hdc"

static inline int magic_to_device(uint8_t magic) {
    /* 返回值：0 = davinci_manager, 1 = hisi_hdc, -1 = 未知 */
    switch (magic) {
        case ASCEND_MAGIC_INIT:
        case ASCEND_MAGIC_CORE:
        case ASCEND_MAGIC_CAPS:
        case ASCEND_MAGIC_CONFIG:
        case ASCEND_MAGIC_DEVOP:
        case ASCEND_MAGIC_EXT:
        case ASCEND_MAGIC_UNKNOWN:
            return 0;
        case ASCEND_MAGIC_HDC:
            return 1;
        default:
            return -1;
    }
}

/* ============================================================
 * seccomp USER_NOTIF 集成
 * ============================================================ */
#define PROXY_SOCKET_PATH  "/tmp/ascend-proxy.sock"

/* Supervisor 与 injector 之间的握手消息 */
struct proxy_handshake {
    uint32_t magic;      /* 0x41534350 "ASCP" */
    uint32_t version;    /* 协议版本 */
    uint32_t pid;        /* 容器进程 pid */
};
#define PROXY_MAGIC      0x41534350
#define PROXY_VERSION    1

#endif /* ASCEND_PROXY_COMMON_H */
