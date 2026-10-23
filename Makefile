# ascend-proxy Makefile
#
# 目标平台：Linux ≥ 5.0, x86_64 或 aarch64
# 依赖：gcc, libc headers（不需要 libseccomp）

CC      ?= gcc
CFLAGS  ?= -std=gnu11 -O2 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
LDFLAGS ?= -lpthread

SRCDIR = src
OBJDIR = build
BINDIR = bin

.PHONY: all clean test check help

all: proxy inject

$(OBJDIR):
	@mkdir -p $(OBJDIR) $(BINDIR)

# ============================================================
# Supervisor 可执行文件
# ============================================================
proxy: $(BINDIR)/ascend-proxy

$(BINDIR)/ascend-proxy: $(SRCDIR)/proxy_main.c $(SRCDIR)/whitelist.c $(SRCDIR)/whitelist.h $(SRCDIR)/common.h | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/proxy_main.c $(SRCDIR)/whitelist.c $(LDFLAGS)

# ============================================================
# LD_PRELOAD 注入器
# ============================================================
inject: $(BINDIR)/inject_seccomp.so

$(BINDIR)/inject_seccomp.so: $(SRCDIR)/inject_seccomp.c $(SRCDIR)/common.h | $(OBJDIR)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $(SRCDIR)/inject_seccomp.c

# ============================================================
# 白名单单元测试（本地跑，不需要内核支持）
# ============================================================
test: $(BINDIR)/test_whitelist
	./$(BINDIR)/test_whitelist

$(BINDIR)/test_whitelist: tests/test_whitelist.c $(SRCDIR)/whitelist.c $(SRCDIR)/whitelist.h $(SRCDIR)/common.h | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ tests/test_whitelist.c $(SRCDIR)/whitelist.c

# ============================================================
# 环境预验证（Phase 2.0）
# ============================================================
check: $(BINDIR)/check_env
	./$(BINDIR)/check_env

$(BINDIR)/check_env: tests/check_env.c | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ tests/check_env.c

# ============================================================
# 清理
# ============================================================
clean:
	rm -rf $(OBJDIR) $(BINDIR)

help:
	@echo "ascend-proxy 构建目标："
	@echo "  make proxy   — 编译 supervisor (bin/ascend-proxy)"
	@echo "  make inject  — 编译 LD_PRELOAD 注入器 (bin/inject_seccomp.so)"
	@echo "  make test    — 白名单单元测试（本地即可跑）"
	@echo "  make check   — 内核 seccomp USER_NOTIF 支持验证（需云容器）"
	@echo "  make all     — 编译 proxy + inject"
	@echo "  make clean   — 清理构建产物"
