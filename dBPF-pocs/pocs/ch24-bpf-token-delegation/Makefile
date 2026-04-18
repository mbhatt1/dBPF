# ch24-bpf-token-delegation — self-contained Makefile
#
# Unlike the other PoCs, this one does NOT use a compile-time libbpf skeleton.
# The userspace loader opens the .bpf.o at runtime via bpf_object__open_file(),
# so no .skel.h is generated. We therefore do not include ../../shared/common.mk
# (which hardcodes skeleton generation as a prerequisite of the final binary).
#
# Layout:
#   ch24-bpf-token-delegation.bpf.c  - kernel-side BPF program
#   ch24-bpf-token-delegation.c      - userspace loader (--server / --client)
#
# Artifacts:
#   build/ch24-bpf-token-delegation.bpf.o  - BTF + CO-RE BPF object (aarch64)
#   build/ch24-bpf-token-delegation        - userspace binary linked with libbpf

APP     := ch24-bpf-token-delegation
BUILD   := build
CLANG   ?= clang
BPFTOOL ?= bpftool

# Cross-compile BPF for aarch64 target regardless of build host arch.
BPF_TARGET_ARCH := arm64

VMLINUX := $(BUILD)/vmlinux.h
BPF_OBJ := $(BUILD)/$(APP).bpf.o
BIN     := $(BUILD)/$(APP)

CFLAGS  := -O2 -g -Wall -Wextra -Werror
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) \
              -I$(BUILD) -I/usr/include/$(shell uname -m)-linux-gnu \
              -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -Wno-gnu-variable-sized-type-not-at-end \
              -Wno-address-of-packed-member -Wno-tautological-compare \
              -Wno-unknown-warning-option -Wno-incompatible-pointer-types

.PHONY: all clean
all: $(BIN) $(BPF_OBJ)

$(BUILD):
	@mkdir -p $(BUILD)

$(VMLINUX): | $(BUILD)
	@echo "  GEN  vmlinux.h"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(APP).bpf.c $(VMLINUX)
	@echo "  BPF  $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@llvm-strip -g $@ 2>/dev/null || true

# NOTE: no skeleton step. The loader opens BPF_OBJ at runtime via
# bpf_object__open_file(). It is still linked against libbpf/libelf/libz
# because it drives the libbpf raw-syscall path (bpf_object__load,
# bpf_program__attach, etc.) directly instead of through skeleton wrappers.
$(BIN): $(APP).c | $(BUILD)
	@echo "  CC   $@"
	@$(CLANG) $(CFLAGS) -I$(BUILD) $< -o $@ -lbpf -lelf -lz

clean:
	rm -rf $(BUILD)
