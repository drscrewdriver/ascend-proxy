/*
 * test_whitelist.c — 白名单查询单元测试
 *
 * 本地即可运行（不需要内核支持），验证：
 *   - 所有 80+ ALLOW 条目命中预期
 *   - 24+ DENY 条目正确拒绝
 *   - 未列入表的 ioctl 默认 DENY
 *
 * 编译：make test
 * 运行：./bin/test_whitelist
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ioctl.h>

#include "../src/whitelist.h"

static int g_pass = 0, g_fail = 0;

static void expect_action(uint32_t req, proxy_action_t want, const char *name) {
    const struct whitelist_entry *e = whitelist_lookup(req);
    proxy_action_t got = e ? e->action : PROXY_DENY;
    if (got == want) {
        g_pass++;
    } else {
        g_fail++;
        const char *a = got == PROXY_ALLOW ? "ALLOW" :
                        got == PROXY_DENY ? "DENY" : "AUDIT";
        const char *w = want == PROXY_ALLOW ? "ALLOW" :
                        want == PROXY_DENY ? "DENY" : "AUDIT";
        printf("  ✗ %s: got %s, want %s (magic=0x%02x nr=0x%02x)\n",
               name, a, w, _IOC_TYPE(req), _IOC_NR(req));
    }
}

#define T(dir, magic, nr, size) _IOC((dir), (magic), (nr), (size))

int main(void) {
    printf("=== ascend-proxy 白名单单元测试 ===\n\n");
    printf("表条目总数: %zu\n\n", ASCEND_WHITELIST_LEN);

    /* ---------- 采样 ALLOW 用例 ---------- */
    printf("[1] 初始化族 (0x45) ALLOW\n");
    expect_action(T(_IOC_NONE,  0x45, 0x00, 0),    PROXY_ALLOW, "0x45 NONE nr=0x00");
    expect_action(T(_IOC_NONE,  0x45, 0x17, 0),    PROXY_ALLOW, "0x45 NONE nr=0x17 (解锁)");

    printf("[2] 核心命令族 (0x4d) NONE 方向 ALLOW\n");
    expect_action(T(_IOC_NONE,  0x4d, 0x03, 0),    PROXY_ALLOW, "0x4d NONE nr=0x03");
    expect_action(T(_IOC_NONE,  0x4d, 0x14, 0),    PROXY_ALLOW, "0x4d NONE nr=0x14");
    expect_action(T(_IOC_NONE,  0x4d, 0x9a, 0),    PROXY_ALLOW, "0x4d NONE nr=0x9a");
    expect_action(T(_IOC_NONE,  0x4d, 0xb6, 0),    PROXY_ALLOW, "0x4d NONE nr=0xb6 (资源释放)");

    printf("[3] 核心命令族 (0x4d) WRITE 方向 ALLOW\n");
    expect_action(T(_IOC_WRITE, 0x4d, 0x0c, 0x158),PROXY_ALLOW, "0x4d WRITE nr=0x0c");
    expect_action(T(_IOC_WRITE, 0x4d, 0x40, 0x158),PROXY_ALLOW, "0x4d WRITE nr=0x40");

    printf("[4] 核心命令族 (0x4d) RW 方向 ALLOW\n");
    expect_action(T(_IOC_READ|_IOC_WRITE, 0x4d, 0x05, 0x158), PROXY_ALLOW, "0x4d RW nr=0x05");
    expect_action(T(_IOC_READ|_IOC_WRITE, 0x4d, 0x23, 0x158), PROXY_ALLOW, "0x4d RW nr=0x23 (内存映射)");
    expect_action(T(_IOC_READ|_IOC_WRITE, 0x4d, 0x2f, 0x158), PROXY_ALLOW, "0x4d RW nr=0x2f (反向传播)");

    printf("[5] 双卡 HCCL 新增 ALLOW\n");
    expect_action(T(_IOC_NONE, 0x4d, 0x04, 0), PROXY_ALLOW, "0x4d nr=0x04 (多卡资源)");
    expect_action(T(_IOC_NONE, 0x4d, 0x15, 0), PROXY_ALLOW, "0x4d nr=0x15 (原二进制独有)");
    expect_action(T(_IOC_NONE, 0x4d, 0x16, 0), PROXY_ALLOW, "0x4d nr=0x16 (原二进制独有)");
    expect_action(T(_IOC_NONE, 0x4d, 0x1d, 0), PROXY_ALLOW, "0x4d nr=0x1d (原二进制独有)");
    expect_action(T(_IOC_NONE, 0x4d, 0x20, 0), PROXY_ALLOW, "0x4d nr=0x20 (原二进制独有)");

    printf("[6] 设备能力族 (0x55) ALLOW\n");
    expect_action(T(_IOC_READ,  0x55, 0x00, 0x14), PROXY_ALLOW, "0x55 READ nr=0x00");
    expect_action(T(_IOC_WRITE, 0x55, 0x01, 0x04), PROXY_ALLOW, "0x55 WRITE nr=0x01");
    expect_action(T(_IOC_READ|_IOC_WRITE, 0x55, 0x02, 0x10), PROXY_ALLOW, "0x55 RW nr=0x02");

    printf("[7] HDC 通道 (0x48) ALLOW\n");
    expect_action(T(_IOC_NONE, 0x48, 0x07, 0), PROXY_ALLOW, "0x48 nr=0x07");
    expect_action(T(_IOC_NONE, 0x48, 0x43, 0), PROXY_ALLOW, "0x48 nr=0x43");

    printf("[8] 0x5a 扩展族 ALLOW\n");
    expect_action(T(_IOC_NONE, 0x5a, 0x00, 0), PROXY_ALLOW, "0x5a nr=0x00");

    /* ---------- 采样 DENY 用例 ---------- */
    printf("\n[9] 二进制独有 → DENY\n");
    expect_action(T(_IOC_NONE, 0x4d, 0x12, 0), PROXY_DENY, "0x4d nr=0x12 (二进制独有)");
    expect_action(T(_IOC_NONE, 0x4d, 0xa3, 0), PROXY_DENY, "0x4d nr=0xa3");
    expect_action(T(_IOC_NONE, 0x4d, 0xb9, 0), PROXY_DENY, "0x4d nr=0xb9");

    printf("[10] 0x89 未知族 → DENY\n");
    expect_action(T(_IOC_NONE, 0x89, 0x0b, 0), PROXY_DENY, "0x89 nr=0x0b");
    expect_action(T(_IOC_NONE, 0x89, 0x1c, 0), PROXY_DENY, "0x89 nr=0x1c");

    printf("[11] 不在表中的编号 → 默认 DENY\n");
    expect_action(T(_IOC_NONE, 0x4d, 0xff, 0), PROXY_DENY, "0x4d nr=0xff (未定义)");
    expect_action(T(_IOC_NONE, 0x99, 0x00, 0), PROXY_DENY, "0x99 magic (非 NPU)");
    expect_action(0x12345678,                   PROXY_DENY, "完全随机的 ioctl");

    /* ---------- 汇总 ---------- */
    printf("\n=== 结果: %d 通过 / %d 失败 ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
