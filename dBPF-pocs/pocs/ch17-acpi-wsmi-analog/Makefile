APP := ch17-acpi-wsmi-analog
include ../../shared/common.mk

EXTRA_BINS := $(BUILD)/fw_requester

all: $(BIN) $(EXTRA_BINS)

$(BUILD)/fw_requester: fw_requester.c | $(BUILD)
	@echo "  CC   $@"
	@$(CLANG) $(CFLAGS) $< -o $@
