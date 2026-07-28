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
# -fdebug-prefix-map rewrites the compilation-directory / source-path strings that
# clang embeds in DWARF (and that bpf2go/bpftool then carry into BTF) so the
# committed .o files never leak a builder's local absolute filesystem path
# (e.g. /home/<user>/... or /Users/<user>/...). We keep -g (and therefore DWARF)
# because CO-RE relies on BTF derived from it — this maps the path, it does not
# strip debug info.
CFLAGS      := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
               -I/usr/include -I/usr/include/x86_64-linux-gnu \
               -fdebug-prefix-map=$(CURDIR)=bpf \
               -Wall -Werror -Wno-pass-failed

BPF_SRCS    := zero_window.c xdp_bridge.c pm_relay.c pm_sk_lookup.c pm_xdp_vtep.c
BPF_OBJECTS := $(BPF_SRCS:.c=.bpf.o)

.PHONY: all clean generate

all: $(BPF_OBJECTS)

%.bpf.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

# generate: produce Go bpf2go bindings for each program and copy .o to bpfloader.
# bpf2go reads the .o, introspects maps/programs via BTF, and emits
# typed Go structs with Load/Close methods — no unsafe casts at runtime.
# Must run on Linux with clang ≥14 and bpf2go installed:
#   go install github.com/cilium/ebpf/cmd/bpf2go@latest
generate: $(BPF_OBJECTS)
	GOPACKAGE=bpfloader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "$(CFLAGS)" \
		-output-dir ../internal/agent/network/bpfloader \
		ZeroWindow ./zero_window.c
	GOPACKAGE=bpfloader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "$(CFLAGS)" \
		-output-dir ../internal/agent/network/bpfloader \
		-output-stem pm_relay \
		PmRelay ./pm_relay.c
	# ADR-0403 C3: bpf2go with no -target emits BOTH pm_relay_bpfel.* and
	# pm_relay_bpfeb.*. The committed tree is bpfel-only for pm_relay; the *.o
	# gitignore drops the stray bpfeb.o but the bpfeb.go is NOT ignored and would
	# be left behind (unlike xdpbridge, which already cleans up). Remove both.
	rm -f ../internal/agent/network/bpfloader/pm_relay_bpfeb.go \
	      ../internal/agent/network/bpfloader/pm_relay_bpfeb.o
	GOPACKAGE=bpfloader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "$(CFLAGS)" \
		-output-dir ../internal/agent/network/bpfloader \
		PmSkLookup ./pm_sk_lookup.c
	GOPACKAGE=bpfloader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "$(CFLAGS)" \
		-output-dir ../internal/agent/network/bpfloader \
		PmXdpVtep ./pm_xdp_vtep.c
	GOPACKAGE=bpfloader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "$(CFLAGS)" \
		-output-dir ../internal/agent/network/bpfloader \
		-no-global-types \
		XdpBridge ./xdp_bridge.c
	rm -f ../internal/agent/network/bpfloader/xdpbridge_bpfeb.go \
	      ../internal/agent/network/bpfloader/xdpbridge_bpfeb.o
	cp zero_window_bpfel.o ../internal/agent/network/bpfloader/zero_window_bpfel.o
	cp zero_window_bpfeb.o ../internal/agent/network/bpfloader/zero_window_bpfeb.o

clean:
	rm -f $(BPF_OBJECTS)
