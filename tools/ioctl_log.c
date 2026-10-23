/**
 * ioctl_log.c — 昇腾 NPU ioctl 全拦截 LD_PRELOAD hook
 *
 * 编译: gcc -shared -fPIC -o ioctl_log.so ioctl_log.c -ldl
 * 使用: LD_PRELOAD=./ioctl_log.so python3 your_script.py 2>/tmp/ioctl_log.txt
 * 分析: grep "\[IOCTL\]" /tmp/ioctl_log.txt | awk '{print $3, $4}' | sort -u
 *
 * 原理: 在用户态 libc 层拦截所有 ioctl() 调用，过滤 NPU 相关 magic 号，
 *       记录 type/nr/dir/size/arg，然后透传给真实 ioctl。
 *       比 strace 更可靠：strace 对未知设备 ioctl 解码有 ~33% 遗漏率。
 *
 * 覆盖 magic: 0x45(初始化), 0x4d(核心命令), 0x55(设备能力),
 *             0x57(配置查询), 0x58(设备操作), 0x5a(扩展),
 *             0x48(hisi_hdc), 0x89(未知/HCCL)
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

typedef int (*orig_ioctl_t)(int, unsigned long, ...);

int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void*);
    va_end(ap);

    /* 提取 magic (type) 字段: bit 8-15 */
    unsigned char type = (request >> 8) & 0xFF;

    /* 只记录昇腾 NPU 相关 magic 号 */
    if (type == 0x45 || type == 0x4d || type == 0x55 ||
        type == 0x57 || type == 0x58 || type == 0x48 ||
        type == 0x5a || type == 0x89) {

        unsigned int dir  = (request >> 30) & 0x3;
        unsigned int size = (request >> 16) & 0x3FFF;
        unsigned int nr   = request & 0xFF;
        const char *dirs[] = {"NONE", "WRITE", "READ", "RW"};

        fprintf(stderr,
            "[IOCTL] fd=%d type=0x%02x nr=0x%02x dir=%s size=0x%x arg=%p\n",
            fd, type, nr, dirs[dir], size, arg);
    }

    /* 透传给真实 ioctl */
    orig_ioctl_t orig = (orig_ioctl_t)dlsym(RTLD_NEXT, "ioctl");
    return orig(fd, request, arg);
}
