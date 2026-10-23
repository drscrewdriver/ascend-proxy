/*
 * check_env.c — Phase 2.0 环境预验证
 *
 * 检查内核是否支持 seccomp USER_NOTIF + 云容器是否有权限
 *
 * 使用：./check_env
 * 退出码：0=支持可开工；非 0=需降级方案
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL 2
#endif

int main(void) {
    printf("=== ascend-proxy 环境预验证 ===\n\n");

    /* 1. 内核版本 */
    struct utsname uts;
    uname(&uts);
    printf("[1] 内核版本: %s\n", uts.release);
    printf("    架构: %s\n", uts.machine);

    /* 2. 检查 seccomp 系统调用可用 */
    long r = syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
                     &(unsigned int){SECCOMP_RET_USER_NOTIF});
    if (r == 0) {
        printf("[2] ✅ 内核支持 SECCOMP_RET_USER_NOTIF\n");
    } else {
        printf("[2] ❌ 内核不支持 USER_NOTIF (errno=%d: %s)\n",
               errno, strerror(errno));
        printf("    → 建议降级到 LD_PRELOAD + unix socket 方案\n");
        return 1;
    }

    /* 3. 检查 CONFIG_SECCOMP_FILTER */
    FILE *f = fopen("/proc/config.gz", "r");
    if (!f) f = fopen("/boot/config-1.0.0", "r");  /* 通用检查 */
    if (f) {
        printf("[3] 内核 config 可读\n");
        fclose(f);
    } else {
        printf("[3] ⚠️  无法读取内核 config（不影响 USER_NOTIF 支持检查）\n");
    }

    /* 4. 检查 CAP_SYS_PTRACE（proxy 需要 process_vm_readv） */
    if (geteuid() == 0) {
        printf("[4] ✅ root 权限（可访问设备 + ptrace）\n");
    } else {
        printf("[4] ⚠️  非 root：需要 CAP_SYS_ADMIN + CAP_SYS_PTRACE\n");
    }

    /* 5. 检查设备文件 */
    if (access("/dev/davinci_manager", R_OK | W_OK) == 0) {
        printf("[5] ✅ /dev/davinci_manager 可读写\n");
    } else {
        printf("[5] ❌ /dev/davinci_manager 不可访问: %s\n", strerror(errno));
        return 2;
    }

    if (access("/dev/hisi_hdc", R_OK | W_OK) == 0) {
        printf("[6] ✅ /dev/hisi_hdc 可读写\n");
    } else {
        printf("[6] ❌ /dev/hisi_hdc 不可访问\n");
        return 2;
    }

    printf("\n=== 环境就绪，可以开工 Phase 2.1 ===\n");
    return 0;
}
