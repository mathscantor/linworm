# Variables
CC := gcc
ARCH ?= x86_64  # Default architecture
CFLAGS := -Wall -Wextra -Wformat -Wformat-overflow -I./src -Iinclude
LDFLAGS := -ldl
SRC_DIR := src
BUILD_DIR := build
TESTS_DIR := tests
PAYLOAD_DIR := $(SRC_DIR)/payload
TARGET := $(BUILD_DIR)/linworm
TEST_TARGET := $(BUILD_DIR)/tests/example_target
PAYLOAD_SRCS := $(filter-out $(PAYLOAD_DIR)/common.c,$(wildcard $(PAYLOAD_DIR)/*.c))
PAYLOADS := $(patsubst $(PAYLOAD_DIR)/%.c,$(BUILD_DIR)/payload/%.so,$(PAYLOAD_SRCS))

# Set compiler and flags based on architecture
ARCH := $(strip $(ARCH))
ifeq ($(ARCH),x86_64)
    CC := gcc
    CFLAGS += -DX86_64
else ifeq ($(ARCH),x86)
    CC := gcc
    CFLAGS += -DX86 -m32
else ifeq ($(ARCH),aarch64)
    CC := aarch64-linux-gnu-gcc
    CFLAGS += -DAARCH64
else ifeq ($(ARCH),arm)
    CC := arm-linux-gnueabihf-gcc
    CFLAGS += -DARM
else
    $(error Unsupported ARCH: $(ARCH). Use ARCH=x86_64, ARCH=x86, ARCH=aarch64, or ARCH=arm)
endif

# Check if the compiler is installed
ifeq ($(shell command -v $(CC) 2>/dev/null),)
    $(error Compiler $(CC) not found! Please install it before proceeding.)
endif

# Source files
SRCS := $(shell find $(SRC_DIR) -type f -name '*.c' -not -path '$(PAYLOAD_DIR)/*' | sort)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

all: $(TARGET) $(TEST_TARGET) $(PAYLOADS)

# Build directory
$(BUILD_DIR):
	mkdir -p $@

# Compile object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

$(TEST_TARGET): $(TESTS_DIR)/example_target.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) -Wall -o $@ $<

$(BUILD_DIR)/payload/%.so: $(PAYLOAD_DIR)/%.c $(PAYLOAD_DIR)/common.c $(PAYLOAD_DIR)/common.h | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) -shared -fPIC -Wall -pthread -o $@ $< $(PAYLOAD_DIR)/common.c

# Clean up
clean:
	rm -rf $(BUILD_DIR)

# Phony targets
.PHONY: all clean