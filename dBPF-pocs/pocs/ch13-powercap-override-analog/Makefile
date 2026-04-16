APP := ch13-powercap-override-analog
include ../../shared/common.mk

# Extra helper binaries: userspace sensor daemon + reader.
EXTRA_BINS := $(BUILD)/sensor_daemon $(BUILD)/sensor_reader

all: $(BIN) $(EXTRA_BINS)

$(BUILD)/sensor_daemon: sensor_daemon.c | $(BUILD)
	@echo "  CC   $@"
	@$(CLANG) $(CFLAGS) $< -o $@

$(BUILD)/sensor_reader: sensor_reader.c | $(BUILD)
	@echo "  CC   $@"
	@$(CLANG) $(CFLAGS) $< -o $@
