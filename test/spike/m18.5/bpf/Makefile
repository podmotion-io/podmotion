CLANG   ?= clang
LLC     ?= llc
BPFTOOL ?= bpftool

KERNEL_HEADERS ?= /usr/include
LIBBPF_INCLUDE ?= /usr/include/bpf

CFLAGS = -O2 -target bpf -D__TARGET_ARCH_arm64 \
         -I$(KERNEL_HEADERS) -I$(LIBBPF_INCLUDE) \
         -Wall -Werror

.PHONY: all clean

all: zero_window.o seq_xlat_noop.o

zero_window.o: zero_window.c
	$(CLANG) $(CFLAGS) -c $< -o $@

seq_xlat_noop.o: seq_xlat_noop.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
