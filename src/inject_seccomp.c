/*
 * inject_seccomp.c — 容器进程侧的 seccomp 注入器（LD_PRELOAD）
 *
 * 用法：LD_PRELOAD=./inject_seccomp.so python3 your_script.py
 *
 * 构造函数 (__attribute__((constructor))) 在库加载时执行：
 *   1. 编译 BPF filter：ioctl 且 magic 命中 NPU → SECCOMP_RET_USER_NOTIF
 *   2. prctl(NO_NEW_PRIVS) → 允许 unpriv 装 filter
 *   3. seccomp(SET_MODE_FILTER, FILTER_FLAG_NEW_LISTENER) → 拿到 listener fd
 *   4. connect 到 supervisor socket → SCM_RIGHTS 传 listener fd
 *
 * 之后容器进程正常执行 ioctl，若命中 filter：
 *   - 内核挂起该 ioctl 调用
 *   - supervisor 收到 NOTIF_RECV → 白名单 → 真 ioctl → NOTIF_SEND
 *   - 容器 ioctl 返回结果，无感知
 *
 * 编译：gcc -shared -fPIC -O2 -Wall -o inject_seccomp.so inject_seccomp.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/utsname.h>

#include "common.h"

/* ============================================================
 * seccomp BPF 常量（部分 header 未导出）
 * ============================================================ */
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

/* ============================================================
 * 构造 BPF 过滤器
 *
 * 逻辑：
 *   if (syscall != __NR_ioctl) ALLOW
 *   magic = (args[1] >> 8) & 0xFF
 *   if (magic in {45,48,4d,55,57,58,5a,89}) USER_NOTIF
 *   else ALLOW
 * ============================================================ */
#define OFF_NR   offsetof(struct seccomp_data, nr)
#define OFF_ARCH offsetof(struct seccomp_data, arch)
#define OFF_CMD  offsetof(struct seccomp_data, args[1])

/* 目标架构 audarch（x86_64 与 aarch64 都覆盖） */
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7
#endif
#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

#define BPF_JUMP_IF_NEQ(idx, val, skip_next) \
    BPF_JUMP(BPF_JMP | BPF_JNE | BPF_K, (val), (skip_next), 0)

static struct sock_filter g_filter[] = {
    /* [0] 载入 syscall nr */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

    /* [1] 非 ioctl 直接跳到 ALLOW([15]): jt=13, jf=0 */
    BPF_JUMP(BPF_JMP | BPF_JNE | BPF_K, __NR_ioctl, 13, 0),

    /* [2] 载入 ioctl cmd (args[1] 低 32 位，小端) */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_CMD),

    /* [3] A >>= 8 */
    BPF_ALU(BPF_ALU | BPF_RSH | BPF_K, 8, 0),
    /* [4] A &= 0xFF → A = magic byte */
    BPF_ALU(BPF_ALU | BPF_AND | BPF_K, 0xFF, 0),

    /* [5-12] 比较 8 个 magic，命中则跳到 NOTIF([14]) */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_INIT,    8, 0),  /* → [14] */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_HDC,     7, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_CORE,    6, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_CAPS,    5, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_CONFIG,  4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_DEVOP,   3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_EXT,     2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_UNKNOWN, 1, 0),

    /* [13] 未命中：无条件跳到 ALLOW([15]) */
    BPF_STMT(BPF_JMP | BPF_JA, 1),

    /* [14] NPU ioctl → USER_NOTIF */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

    /* [15] 其他 → ALLOW */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

/* ============================================================
 * SCM_RIGHTS 发送 fd
 * ============================================================ */
static int send_fd(int sock, int fd_to_send) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec iov;
    char dummy = 'F';

    iov.iov_base = &dummy;
    iov.iov_len = 1;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = fd_to_send;

    return sendmsg(sock, &msg, 0) >= 0 ? 0 : -1;
}

/* ============================================================
 * 安装 seccomp filter + 连接 supervisor
 * ============================================================ */
static int install_seccomp_and_connect(void) {
    /* 1. 设置 NO_NEW_PRIVS（unpriv 装 filter 必须） */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "[inject] PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
        return -1;
    }

    /* 2. 编译 filter 到 sock_fprog */
    struct sock_fprog prog = {
        .len = sizeof(g_filter) / sizeof(g_filter[0]),
        .filter = g_filter,
    };

    /* 3. 装 filter 并要求返回 listener fd */
    int listener = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                           SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener < 0) {
        fprintf(stderr, "[inject] seccomp(SET_MODE_FILTER, NEW_LISTENER): %s\n",
                strerror(errno));
        fprintf(stderr, "[inject] 提示：需要 Linux ≥ 5.0 + CONFIG_SECCOMP_FILTER=y\n");
        return -1;
    }
    fprintf(stderr, "[inject] seccomp listener fd=%d\n", listener);

    /* 4. 连接 supervisor unix socket */
    const char *sock_path = getenv("ASCEND_PROXY_SOCKET");
    if (!sock_path) sock_path = PROXY_SOCKET_PATH;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); close(listener); return -1; }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[inject] connect(%s): %s\n", sock_path, strerror(errno));
        fprintf(stderr, "[inject] 请确认 ascend-proxy supervisor 已启动\n");
        close(sock);
        close(listener);
        return -1;
    }

    /* 5. 传 listener fd 给 supervisor */
    if (send_fd(sock, listener) < 0) {
        fprintf(stderr, "[inject] send_fd failed: %s\n", strerror(errno));
        close(sock);
        close(listener);
        return -1;
    }

    /* 6. 保活：socket 保持打开，让 supervisor 通过 listener fd 收通知
          注意：本地 listener fd 也保持打开（不关闭，防止引用计数归零） */
    fprintf(stderr, "[inject] proxy connected, sock=%d listener=%d\n", sock, listener);
    return 0;
}

/* ============================================================
 * 构造函数：LD_PRELOAD 加载时自动执行
 * ============================================================ */
__attribute__((constructor))
static void ascend_proxy_inject_ctor(void) {
    /* 通过环境变量控制是否启用（默认启用） */
    const char *disable = getenv("ASCEND_PROXY_DISABLE");
    if (disable && strcmp(disable, "1") == 0) {
        fprintf(stderr, "[inject] disabled via ASCEND_PROXY_DISABLE=1\n");
        return;
    }

    if (install_seccomp_and_connect() < 0) {
        fprintf(stderr, "[inject] FATAL: cannot install proxy\n");
        /* 不 exit，让进程自己决定；生产环境可以改成 abort */
    }
}
