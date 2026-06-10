# bpf/Makefile — compile eBPF C programs to .o and generate Go bindings.
#
# Requirements on the build host:
#   clang >= 14          (for CO-RE / BTF support)
#   llvm                 (for bpf target)
#   linux-headers or bpftool for vmlinux.h generation
#   github.com/cilium/ebpf/cmd/bpf2go  (installed via go install)
#
# The .o files are committed to the repo so that nodes without a full clang
# toolchain can still load the programs.  The Go bindings (bpf_*_bpfel.go)
# are generated from the .o files via bpf2go and are also committed.

CLANG       ?= clang
CFLAGS      := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
               -I/usr/include -I/usr/include/x86_64-linux-gnu \
               -Wall -Werror

BPF_SRCS    := zero_window.c xdp_bridge.c
BPF_OBJECTS := $(BPF_SRCS:.c=.bpf.o)

.PHONY: all clean generate

all: $(BPF_OBJECTS)

%.bpf.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

# generate: produce Go bpf2go bindings for each program.
# bpf2go reads the .o, introspects maps/programs via BTF, and emits
# typed Go structs with Load/Close methods — no unsafe casts at runtime.
generate:
	go generate ./bpf/...

clean:
	rm -f $(BPF_OBJECTS)
