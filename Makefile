# SPDX-License-Identifier: BSD-3-Clause
# Build the unified USB Sniffer capture library / usbpv plugin.
#
# Linux compile check:       make
# Windows (MSYS2 MinGW) DLL: make PLUGIN_EXT=dll CC=gcc
#
# Needs libusb-1.0 development files (MSYS2: mingw-w64-x86_64-libusb).

CC       ?= cc
PLUGIN_EXT ?= so

INCLUDES := -I.
CFLAGS   ?= -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function $(INCLUDES)

PKGCONFIG     ?= pkg-config
LIBUSB_CFLAGS := $(shell $(PKGCONFIG) --cflags libusb-1.0 2>/dev/null)
LIBUSB_LIBS   := $(shell $(PKGCONFIG) --libs libusb-1.0 2>/dev/null || echo -lusb-1.0)

override CFLAGS += $(LIBUSB_CFLAGS)
override CFLAGS += $(EXTRA_DEFS)
LDLIBS   ?= $(LIBUSB_LIBS) -lpthread
LDFLAGS  ?= -Wl,--no-undefined
override CFLAGS  += -ffunction-sections -fdata-sections
override LDFLAGS += -Wl,--gc-sections

ifeq ($(PLUGIN_EXT),dll)
  # Self-contained DLL: statically link libusb-1.0, libgcc and winpthread so
  # usbpv can load it without shipping any extra DLLs next to usbpv.exe.
  # --exclude-all-symbols: export only our __declspec(dllexport) ABI (avoid
  # MinGW auto-exporting libusb/pthread/etc. which can collide in the host).
  override LDFLAGS += -static -static-libgcc -s -Wl,--exclude-all-symbols
  override LDLIBS  := -lusb-1.0 -lpthread
endif

OUT    := out
OBJ    := $(OUT)/obj
SRC    := $(wildcard *.c)
OBJS   := $(patsubst %.c,$(OBJ)/%.o,$(SRC))

# Windows DLL goes straight into plugins/ so it can be dropped next to usbpv.
ifeq ($(PLUGIN_EXT),dll)
  TARGET := plugins/usb_sniffer.dll
else
  TARGET := $(OUT)/usb_sniffer.$(PLUGIN_EXT)
endif

.PHONY: all clean
all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

clean:
	rm -rf $(OUT) plugins
