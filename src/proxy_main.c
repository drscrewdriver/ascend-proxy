/*
 * proxy_main.c — ascend-proxy supervisor
 *
 * 主流程：
 *   1. 打开真实设备 fd（davinci_manager + hisi_hdc）
 *   2. 建立 unix socket listener，接受容器 injector 连接
 *   3. 收到 SCM_RIGHTS 传来的 seccomp listener fd 后加入 epoll
 *   4. epoll 主循环：NOTIF_RECV → 白名单查询 → 真 ioctl → NOTIF_SEND
 *
 * 编译：gcc -O2 -Wall -o ascend-proxy proxy_main.c whitelist.c -lpthread
 * 需要：root 或 CAP_SYS_ADMIN + CAP_SYS_PTRACE
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#include "common.h"
#include "whitelist.h"

/* ============================================================
 * seccomp USER_NOTIF 结构体（部分 libc 未导出）
 * ============================================================ */
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

struct seccomp_notif_resp {
    __u64 id;
    __s64 val;
    __s32 error;
    __u32 flags;
};

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV \
    _IOWR('!', 0, struct seccomp_notif)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_SEND
#define SECCOMP_IOCTL_NOTIF_SEND \
    _IOWR('!', 1, struct seccomp_notif_resp)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ID_VALID
#define SECCOMP_IOCTL_NOTIF_ID_VALID \
    _IOW('!', 2, __u64)
#endif

/* ============================================================
 * 运行时状态
 * ============================================================ */
static int g_davinci_fd = -1;
static int g_hdc_fd     = -1;
static int g_listen_fd  = -1;
static int g_epoll_fd   = -1;
static volatile int g_running = 1;

static int g_verbose = 0;
static int g_stats_only = 0;

/* 每个连接（容器进程）一个 tracking 结构 */
#define MAX_SESSIONS 64
struct session {
    int      notif_fd;    /* seccomp listener fd，从 injector 通过 SCM_RIGHTS 传来 */
    int      conn_fd;     /* unix socket 连接到 injector 的 fd */
    pid_t    remote_pid;
    int      active;
    uint64_t ioctl_count;
    uint64_t deny_count;
};
static struct session g_sessions[MAX_SESSIONS];

/* ============================================================
 * 工具函数
 * ============================================================ */
static void logmsg(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[proxy] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* 从 ioctl_req 提取 size 用于内存缓冲区分配 */
static size_t ioctl_size(uint32_t req) {
    size_t sz = _IOC_SIZE(req);
    /* 上限保护：昇腾最大观测 size = 0x158 = 344B；保险取 4KB */
    if (sz == 0) return 0;
    if (sz > 4096) sz = 4096;
    return sz;
}

/* 跨进程读参数 */
static int read_remote_buf(pid_t pid, uint64_t remote_addr, void *local, size_t len) {
    if (len == 0 || remote_addr == 0) return 0;
    struct iovec local_iov  = { .iov_base = local, .iov_len = len };
    struct iovec remote_iov = { .iov_base = (void *)remote_addr, .iov_len = len };
    ssize_t n = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    return n == (ssize_t)len ? 0 : -1;
}

static int write_remote_buf(pid_t pid, uint64_t remote_addr, const void *local, size_t len) {
    if (len == 0 || remote_addr == 0) return 0;
    struct iovec local_iov  = { .iov_base = (void *)local, .iov_len = len };
    struct iovec remote_iov = { .iov_base = (void *)remote_addr, .iov_len = len };
    ssize_t n = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    return n == (ssize_t)len ? 0 : -1;
}

/* 按 magic 选择真实设备 fd */
static int pick_real_fd(uint32_t req) {
    int dev = magic_to_device(_IOC_TYPE(req));
    if (dev == 0) return g_davinci_fd;
    if (dev == 1) return g_hdc_fd;
    return -1;
}

/* 通知 ID 有效性检查（防止容器进程已退出） */
static int is_notif_id_valid(int notif_fd, uint64_t id) {
    return ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

/* ============================================================
 * SCM_RIGHTS：接收来自 injector 的 listener fd
 * ============================================================ */
static int recv_fd(int conn) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec iov;
    char dummy = 0;
    iov.iov_base = &dummy;
    iov.iov_len = 1;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    if (recvmsg(conn, &msg, 0) < 0) return -1;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS) {
        return -1;
    }
    return *(int *)CMSG_DATA(cmsg);
}

/* ============================================================
 * 处理一个 seccomp 通知
 * ============================================================ */
static void handle_notif(struct session *sess) {
    struct seccomp_notif req = {0};
    struct seccomp_notif_resp resp = {0};

    if (ioctl(sess->notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
        if (errno == EINTR) return;
        logmsg("NOTIF_RECV failed: %s", strerror(errno));
        sess->active = 0;
        return;
    }

    resp.id = req.id;
    sess->ioctl_count++;

    /* seccomp_data 布局：args[0]=fd, args[1]=cmd, args[2]=arg */
    uint32_t cmd  = (uint32_t)req.data.args[1];
    uint64_t argp = req.data.args[2];

    /* 非 NPU ioctl 直接放行（injector 应该已经在 filter 里放行，
       这里做二次防御） */
    if (!ASCEND_IS_NPU_IOCTL(cmd)) {
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        goto send;
    }

    /* 白名单查询 */
    const struct whitelist_entry *e = whitelist_lookup(cmd);
    proxy_action_t act = e ? e->action : PROXY_DENY;

    if (act == PROXY_DENY) {
        sess->deny_count++;
        logmsg("DENY magic=0x%02x nr=0x%02x dir=%d size=0x%x pid=%d",
               _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_DIR(cmd), _IOC_SIZE(cmd), req.pid);
        resp.error = -EPERM;
        goto send;
    }

    if (!is_notif_id_valid(sess->notif_fd, req.id)) {
        logmsg("notif id invalid, skip");
        goto send;
    }

    /* 分配缓冲区读容器进程的 arg */
    size_t sz = ioctl_size(cmd);
    void *buf = NULL;
    if (sz > 0 && argp != 0) {
        buf = malloc(sz);
        if (!buf) { resp.error = -ENOMEM; goto send; }
        if (read_remote_buf(req.pid, argp, buf, sz) < 0) {
            logmsg("process_vm_readv failed: %s", strerror(errno));
            free(buf);
            resp.error = -EFAULT;
            goto send;
        }
    }

    /* 执行真实 ioctl */
    int real_fd = pick_real_fd(cmd);
    int ret;
    if (real_fd < 0) {
        resp.error = -ENODEV;
        if (buf) free(buf);
        goto send;
    }
    ret = ioctl(real_fd, cmd, buf);
    int err = errno;

    /* 若 dir 含 READ 位，把 buf 内容回写 */
    if (ret >= 0 && sz > 0 && buf && (_IOC_DIR(cmd) & _IOC_READ)) {
        if (write_remote_buf(req.pid, argp, buf, sz) < 0) {
            logmsg("process_vm_writev failed: %s", strerror(errno));
        }
    }
    if (buf) free(buf);

    if (ret < 0) {
        resp.error = -err;
    } else {
        resp.val = ret;
    }
    logmsg("ALLOW magic=0x%02x nr=0x%02x ret=%d errno=%d",
           _IOC_TYPE(cmd), _IOC_NR(cmd), ret, err);

send:
    if (ioctl(sess->notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        if (errno != ENOENT) {
            logmsg("NOTIF_SEND failed: %s", strerror(errno));
        }
    }
}

/* ============================================================
 * 接受新连接（injector 通过 SCM_RIGHTS 传来 listener fd）
 * ============================================================ */
static void accept_new_session(void) {
    int conn = accept(g_listen_fd, NULL, NULL);
    if (conn < 0) return;

    int notif_fd = recv_fd(conn);
    if (notif_fd < 0) {
        logmsg("recv_fd failed");
        close(conn);
        return;
    }

    /* 找空槽 */
    struct session *sess = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].active) { sess = &g_sessions[i]; break; }
    }
    if (!sess) {
        logmsg("too many sessions, drop");
        close(notif_fd);
        close(conn);
        return;
    }

    sess->notif_fd = notif_fd;
    sess->conn_fd = conn;
    sess->active = 1;
    sess->ioctl_count = 0;
    sess->deny_count = 0;

    /* 加入 epoll */
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = sess };
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, notif_fd, &ev);
    logmsg("session accepted, notif_fd=%d", notif_fd);
}

static void close_session(struct session *sess) {
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, sess->notif_fd, NULL);
    close(sess->notif_fd);
    close(sess->conn_fd);
    sess->active = 0;
    logmsg("session closed (ioctls=%lu, denied=%lu)",
           (unsigned long)sess->ioctl_count, (unsigned long)sess->deny_count);
}

/* ============================================================
 * 初始化
 * ============================================================ */
static int open_devices(void) {
    g_davinci_fd = open(DEV_DAVINCI_MGR, O_RDWR | O_CLOEXEC);
    if (g_davinci_fd < 0) {
        fprintf(stderr, "open %s failed: %s\n", DEV_DAVINCI_MGR, strerror(errno));
        return -1;
    }
    g_hdc_fd = open(DEV_HDC, O_RDWR | O_CLOEXEC);
    if (g_hdc_fd < 0) {
        fprintf(stderr, "open %s failed: %s\n", DEV_HDC, strerror(errno));
        close(g_davinci_fd);
        return -1;
    }
    logmsg("devices opened: davinci=%d hdc=%d", g_davinci_fd, g_hdc_fd);
    return 0;
}

static int setup_socket(void) {
    g_listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_listen_fd < 0) return -1;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, PROXY_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    unlink(PROXY_SOCKET_PATH);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return -1;
    if (listen(g_listen_fd, 8) < 0) return -1;
    logmsg("socket listening on %s", PROXY_SOCKET_PATH);
    return 0;
}

/* ============================================================
 * 主循环
 * ============================================================ */
int main(int argc, char **argv) {
    static struct option opts[] = {
        { "verbose", no_argument, 0, 'v' },
        { 0, 0, 0, 0 }
    };
    int c;
    while ((c = getopt_long(argc, argv, "v", opts, NULL)) != -1) {
        if (c == 'v') g_verbose = 1;
    }

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (open_devices() < 0) return 1;
    if (setup_socket() < 0) {
        perror("setup_socket");
        return 1;
    }

    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = NULL };
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_listen_fd, &ev);

    printf("ascend-proxy ready: %zu whitelist entries (%d verbose)\n",
           ASCEND_WHITELIST_LEN, g_verbose);
    fflush(stdout);

    struct epoll_event events[16];
    while (g_running) {
        int n = epoll_wait(g_epoll_fd, events, 16, 500);
        for (int i = 0; i < n; i++) {
            if (events[i].data.ptr == NULL) {
                accept_new_session();
            } else {
                struct session *s = events[i].data.ptr;
                handle_notif(s);
                if (!s->active) close_session(s);
            }
        }
    }

    /* 清理 */
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].active) close_session(&g_sessions[i]);
    }
    close(g_listen_fd);
    close(g_davinci_fd);
    close(g_hdc_fd);
    unlink(PROXY_SOCKET_PATH);
    return 0;
}
