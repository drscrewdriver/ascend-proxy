/*
 * whitelist.h — 昇腾 NPU ioctl 白名单查询接口
 *
 * 数据来源：docs/ascend-ioctl-catalog.md
 *   - 运行时确认（LD_PRELOAD 单卡+双卡）：82 种 → ALLOW
 *   - 二进制独有（libascend_hal.so）：~24 种 → DENY
 *   - 未列出的所有编号 → DENY (deny-by-default)
 */
#ifndef ASCEND_PROXY_WHITELIST_H
#define ASCEND_PROXY_WHITELIST_H

#include <stdint.h>
#include "common.h"

/* 白名单条目：按 magic+nr 匹配（dir/size 仅记录用于日志） */
struct whitelist_entry {
    uint8_t        magic;
    uint8_t        nr;
    uint8_t        dir;         /* 观测到的方向，用于日志（不参与匹配） */
    uint16_t       size;        /* 观测到的 size，用于日志 */
    proxy_action_t action;
    sec_level_t    sec;
    const char    *desc;        /* 简短功能说明 */
};

/* 表条目数 */
extern const struct whitelist_entry ASCEND_WHITELIST[];
extern const size_t                  ASCEND_WHITELIST_LEN;

/* 查询：命中返回条目指针；未命中返回 NULL */
const struct whitelist_entry *whitelist_lookup(uint32_t ioctl_req);

/* 决策：查询 + 默认 DENY 兜底 */
static inline proxy_action_t whitelist_decide(uint32_t ioctl_req) {
    const struct whitelist_entry *e = whitelist_lookup(ioctl_req);
    return e ? e->action : PROXY_DENY;
}

#endif /* ASCEND_PROXY_WHITELIST_H */
