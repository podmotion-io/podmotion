CLANG   ?= clang
LLC     ?= llc
BPFTOOL ?= bpftool

# Detect arch-specific uapi include path (needed for asm/types.h on arm64/amd64)
ARCH          ?= $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/;s/aarch64/aarch64-linux-gnu/')
KERNEL_HEADERS ?= /usr/include
ARCH_INCLUDE  ?= /usr/include/$(ARCH)
LIBBPF_INCLUDE ?= /usr/include/bpf

CFLAGS = -O2 -target bpf -D__TARGET_ARCH_arm64 \
         -I$(KERNEL_HEADERS) -I$(ARCH_INCLUDE) -I$(LIBBPF_INCLUDE) \
         -Wall -Werror

.PHONY: all clean

all: zero_window.o seq_xlat_noop.o

zero_window.o: zero_window.c
	$(CLANG) $(CFLAGS) -c $< -o $@

seq_xlat_noop.o: seq_xlat_noop.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
