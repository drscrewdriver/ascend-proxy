# ascend-proxy Makefile
#
# 目标平台：Linux ≥ 5.0, x86_64 或 aarch64
# 依赖：gcc, libc headers（不需要 libseccomp）
#
# WSL2 可跑：make test / make lint / make asan
# 云容器需要：make check / 端到端测试（真 NPU）

CC      ?= gcc
BASE_CFLAGS = -std=gnu11 -O2 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
CFLAGS  ?= $(BASE_CFLAGS)
LDFLAGS ?= -lpthread

# Strict / sanitizer variants
STRICT_CFLAGS = $(BASE_CFLAGS) -Werror -Wpedantic -Wshadow -Wconversion
ASAN_CFLAGS   = $(BASE_CFLAGS) -g -fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_LDFLAGS  = $(LDFLAGS) -fsanitize=address,undefined

SRCDIR = src
OBJDIR = build
BINDIR = bin
COVDIR = coverage

.PHONY: all clean test test-strict check lint cppcheck asan help dev verify

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
# 单元测试（WSL2 可跑）
# ============================================================
test: $(BINDIR)/test_whitelist $(BINDIR)/test_filter
	@echo "--- whitelist tests ---"
	./$(BINDIR)/test_whitelist
	@echo ""
	@echo "--- BPF filter tests ---"
	./$(BINDIR)/test_filter

$(BINDIR)/test_whitelist: tests/test_whitelist.c $(SRCDIR)/whitelist.c $(SRCDIR)/whitelist.h $(SRCDIR)/common.h | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ tests/test_whitelist.c $(SRCDIR)/whitelist.c

$(BINDIR)/test_filter: tests/test_filter.c $(SRCDIR)/common.h | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ tests/test_filter.c

# ============================================================
# 严格编译（作为 CI 门禁）
# ============================================================
test-strict:
	$(CC) $(STRICT_CFLAGS) -o $(BINDIR)/test_whitelist_strict \
		tests/test_whitelist.c $(SRCDIR)/whitelist.c
	$(CC) $(STRICT_CFLAGS) -o $(BINDIR)/test_filter_strict tests/test_filter.c
	./$(BINDIR)/test_whitelist_strict
	./$(BINDIR)/test_filter_strict

# ============================================================
# Sanitizer 版本
# ============================================================
asan:
	$(CC) $(ASAN_CFLAGS) -o $(BINDIR)/test_whitelist_asan \
		tests/test_whitelist.c $(SRCDIR)/whitelist.c
	$(CC) $(ASAN_CFLAGS) -o $(BINDIR)/test_filter_asan tests/test_filter.c
	$(CC) $(ASAN_CFLAGS) -o $(BINDIR)/ascend-proxy_asan \
		$(SRCDIR)/proxy_main.c $(SRCDIR)/whitelist.c $(ASAN_LDFLAGS)
	@echo "=== ASan builds ready in $(BINDIR)/ ==="
	@echo "Run: $(BINDIR)/test_whitelist_asan"

# ============================================================
# 静态分析
# ============================================================
lint:
	$(CC) $(STRICT_CFLAGS) -fsyntax-only $(SRCDIR)/whitelist.c
	$(CC) $(STRICT_CFLAGS) -fsyntax-only $(SRCDIR)/proxy_main.c
	$(CC) $(STRICT_CFLAGS) -fsyntax-only $(SRCDIR)/inject_seccomp.c
	@echo "✅ -Werror -Wpedantic -Wshadow -Wconversion 全部通过"

cppcheck:
	@command -v cppcheck >/dev/null 2>&1 || { echo "cppcheck 未安装：sudo apt install cppcheck"; exit 1; }
	cppcheck --error-exitcode=1 --enable=warning,performance,portability \
		--suppress=missingIncludeSystem \
		--inline-suppr $(SRCDIR)/*.c $(SRCDIR)/*.h
	@echo "✅ cppcheck 通过"

# ============================================================
# 云容器专属（Phase 2.0 环境预验证）
# ============================================================
check: $(BINDIR)/check_env
	./$(BINDIR)/check_env

$(BINDIR)/check_env: tests/check_env.c | $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ tests/check_env.c

# ============================================================
# 一键开发循环（WSL2）
# ============================================================
dev: lint test
	@echo "=== dev 循环完成：lint + unit test 全过 ==="

# 提交前门禁
verify: lint cppcheck test-strict
	@echo "=== verify 门禁全过，可以提交 ==="

# ============================================================
clean:
	rm -rf $(OBJDIR) $(BINDIR) $(COVDIR)

help:
	@echo "ascend-proxy 构建目标："
	@echo ""
	@echo "  ── WSL2 本地开发 ──"
	@echo "  make dev          — lint + unit test（快速循环）"
	@echo "  make test         — 白名单 + BPF 过滤器单元测试"
	@echo "  make lint         — -Werror -Wpedantic 严格编译检查"
	@echo "  make cppcheck     — cppcheck 静态分析"
	@echo "  make asan         — 生成 ASan/UBSan 版本二进制"
	@echo "  make verify       — 提交前门禁（lint + cppcheck + strict test）"
	@echo ""
	@echo "  ── 云容器专属 ──"
	@echo "  make check        — Phase 2.0 内核 seccomp USER_NOTIF 支持验证"
	@echo "  make all          — 编译 proxy + inject（生产）"
	@echo ""
	@echo "  make clean        — 清理构建产物"
