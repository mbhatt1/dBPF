# common.mk — shared BPF build rules (libbpf-skeleton style)
# Expects each POC Makefile to set: APP := <name>
# Directory layout:
#   <APP>.bpf.c   - kernel-side BPF program
#   <APP>.c       - user-space loader
#
# Artifacts land in ./build/

APP     ?= poc
BUILD   ?= build
CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/armv7l/arm/')

VMLINUX := $(BUILD)/vmlinux.h
SKEL    := $(BUILD)/$(APP).skel.h
BPF_OBJ := $(BUILD)/$(APP).bpf.o
BIN     := $(BUILD)/$(APP)

CFLAGS  := -O2 -g -Wall -Wextra -Werror
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I$(BUILD) -I/usr/include/$(shell uname -m)-linux-gnu \
              -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -Wno-gnu-variable-sized-type-not-at-end \
              -Wno-address-of-packed-member -Wno-tautological-compare \
              -Wno-unknown-warning-option -Wno-incompatible-pointer-types

.PHONY: all clean run
all: $(BIN)

$(BUILD):
	@mkdir -p $(BUILD)

$(VMLINUX): | $(BUILD)
	@echo "  GEN  vmlinux.h"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(APP).bpf.c $(VMLINUX)
	@echo "  BPF  $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@llvm-strip -g $@ 2>/dev/null || true

$(SKEL): $(BPF_OBJ)
	@echo "  SKEL $@"
	@$(BPFTOOL) gen skeleton $< > $@

$(BIN): $(APP).c $(SKEL)
	@echo "  CC   $@"
	@$(CLANG) $(CFLAGS) -I$(BUILD) $< -o $@ -lbpf -lelf -lz

clean:
	rm -rf $(BUILD)
