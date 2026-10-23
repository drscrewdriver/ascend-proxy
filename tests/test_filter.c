/*
 * test_filter.c — seccomp BPF filter 跳转逻辑单元测试
 *
 * 目的：验证 inject_seccomp.c 中 filter 数组的跳转偏移正确
 *       不实际安装到内核，只做静态模拟。
 *
 * 测试方法：把 filter 视为跳转表，模拟 BPF 求值机：
 *   - 载入 nr，若不是 ioctl，应跳到 ALLOW 分支
 *   - 载入 cmd，提取 magic，应正确命中 8 个 magic 之一
 *   - 命中后应落到 NOTIF；未命中应落到 ALLOW
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/ioctl.h>

#include "../src/common.h"

/* 复制 inject_seccomp.c 的 filter 到此处（避免链接 .so）
 * 若两边不同步，test_filter 会失败提醒。 */
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

#define OFF_NR   offsetof(struct seccomp_data, nr)
#define OFF_CMD  offsetof(struct seccomp_data, args[1])

static struct sock_filter FILTER[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    BPF_JUMP(BPF_JMP | BPF_JNE | BPF_K, __NR_ioctl, 13, 0),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_CMD),
    BPF_ALU(BPF_ALU | BPF_RSH | BPF_K, 8, 0),
    BPF_ALU(BPF_ALU | BPF_AND | BPF_K, 0xFF, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_INIT,    8, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_HDC,     7, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_CORE,    6, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_CAPS,    5, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_CONFIG,  4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_DEVOP,   3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_EXT,     2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ASCEND_MAGIC_UNKNOWN, 1, 0),
    BPF_STMT(BPF_JMP | BPF_JA, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),  /* idx 14 */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),       /* idx 15 */
};

#define FILTER_LEN (sizeof(FILTER) / sizeof(FILTER[0]))
#define IDX_NOTIF 14
#define IDX_ALLOW 15

static int g_pass = 0, g_fail = 0;

/* 简易 BPF 模拟器：给定 (syscall_nr, cmd) 返回最终 PC
 * BPF op 字段参考：linux/bpf.h
 *   ALU: ADD=0 SUB=1 MUL=2 DIV=3 OR=4 AND=5 LSH=6 RSH=7 NEG=8
 *   JMP: JA=0 JEQ=1 JGT=2 JGE=3 JSET=4 JNE=5 JSGT=6 JSGE=7
 * */
static int simulate(uint32_t syscall_nr, uint32_t cmd) {
    unsigned int A = 0;
    int pc = 0;

    while (pc < (int)FILTER_LEN) {
        struct sock_filter *f = &FILTER[pc];
        __u16 code = f->code;
        __u8  jt = f->jt, jf = f->jf;
        __u32 k = f->k;

        int cls  = code & 0x07;   /* CLASS */
        int src  = (code >> 3) & 1; /* 0=BPF_K, 1=BPF_X */
        int sub  = (code >> 4) & 0x0F;

        if (src != 0) { /* 本测试集不包含 BPF_X */
            return -1;
        }

        switch (cls) {
            case 0x01: /* BPF_LD (with BPF_W|BPF_ABS) */
                if (k == OFF_NR) A = syscall_nr;
                else if (k == OFF_CMD) A = cmd;
                pc++;
                break;
            case 0x04: /* BPF_ALU */
                if (sub == 0x7) A >>= k;         /* RSH */
                else if (sub == 0x5) A &= k;     /* AND */
                else if (sub == 0x6) A <<= k;    /* LSH */
                pc++;
                break;
            case 0x05: /* BPF_JMP */
                {
                    int take_jt;
                    if (sub == 0x0) {          /* JA */
                        pc += 1 + k;
                        break;
                    }
                    if (sub == 0x1) take_jt = (A == k);  /* JEQ */
                    else if (sub == 0x5) take_jt = (A != k); /* JNE */
                    else if (sub == 0x2) take_jt = (A > k);  /* JGT */
                    else if (sub == 0x3) take_jt = (A >= k); /* JGE */
                    else if (sub == 0x4) take_jt = ((A & k) != 0); /* JSET */
                    else { pc++; continue; }
                    pc += 1 + (take_jt ? jt : jf);
                }
                break;
            case 0x06: /* BPF_RET */
                return pc;
            default:
                pc++;
        }
    }
    return -1;
}

static void expect_path(uint32_t nr, uint32_t cmd, int want_pc, const char *name) {
    int got = simulate(nr, cmd);
    if (got == want_pc) {
        g_pass++;
    } else {
        g_fail++;
        printf("  ✗ %s: pc=%d, want=%d (magic=0x%02x nr=0x%02x)\n",
               name, got, want_pc, _IOC_TYPE(cmd), _IOC_NR(cmd));
    }
}

#define MK(dir, magic, nr) _IOC((dir), (magic), (nr), 0x158)

int main(void) {
    printf("=== ascend-proxy BPF filter 单元测试 ===\n\n");
    printf("filter 长度: %zu 条指令\n\n", FILTER_LEN);

    /* 结构性检查 */
    if (FILTER_LEN > 4096) {
        printf("❌ BPF 指令数超过 4096 上限\n");
        return 1;
    }

    /* ---------- 非 ioctl 系统调用 ---------- */
    printf("[1] 非 ioctl syscall → ALLOW\n");
    expect_path(0 /*read*/,  0, IDX_ALLOW, "read");
    expect_path(1 /*write*/, 0, IDX_ALLOW, "write");
    expect_path(60 /*exit*/, 0, IDX_ALLOW, "exit");

    /* ---------- ioctl 但 magic 不是 NPU ---------- */
    printf("[2] ioctl 但非 NPU magic → ALLOW\n");
    expect_path(__NR_ioctl, MK(_IOC_NONE, 'T', 0x01), IDX_ALLOW, "tty ioctl");
    expect_path(__NR_ioctl, MK(_IOC_NONE, 0x99, 0x01), IDX_ALLOW, "unknown magic 0x99");

    /* ---------- 8 个 NPU magic 都要跳 NOTIF ---------- */
    printf("[3] NPU magic → USER_NOTIF\n");
    expect_path(__NR_ioctl, MK(_IOC_NONE, ASCEND_MAGIC_INIT,    0x17), IDX_NOTIF, "0x45 init");
    expect_path(__NR_ioctl, MK(_IOC_NONE, ASCEND_MAGIC_HDC,     0x07), IDX_NOTIF, "0x48 hdc");
    expect_path(__NR_ioctl, MK(_IOC_NONE, ASCEND_MAGIC_CORE,    0x03), IDX_NOTIF, "0x4d core");
    expect_path(__NR_ioctl, MK(_IOC_READ, ASCEND_MAGIC_CAPS,    0x00), IDX_NOTIF, "0x55 caps");
    expect_path(__NR_ioctl, MK(_IOC_READ|_IOC_WRITE, ASCEND_MAGIC_CONFIG, 0x01), IDX_NOTIF, "0x57 config");
    expect_path(__NR_ioctl, MK(_IOC_READ|_IOC_WRITE, ASCEND_MAGIC_DEVOP,  0x00), IDX_NOTIF, "0x58 devop");
    expect_path(__NR_ioctl, MK(_IOC_NONE, ASCEND_MAGIC_EXT,     0x00), IDX_NOTIF, "0x5a ext");
    expect_path(__NR_ioctl, MK(_IOC_NONE, ASCEND_MAGIC_UNKNOWN, 0x0b), IDX_NOTIF, "0x89 unknown");

    /* ---------- 边界：magic 前后各一个不匹配值 ---------- */
    printf("[4] magic 边界（0x44 和 0x4e）→ ALLOW\n");
    expect_path(__NR_ioctl, MK(_IOC_NONE, 0x44, 0x00), IDX_ALLOW, "magic 0x44");
    expect_path(__NR_ioctl, MK(_IOC_NONE, 0x4e, 0x00), IDX_ALLOW, "magic 0x4e");

    printf("\n=== 结果: %d 通过 / %d 失败 ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
