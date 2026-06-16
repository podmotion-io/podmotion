/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// cmd/holder is the universal no-op holder binary injected into replacement pods
// via an init-container + emptyDir side-load (ADR-0195 Rule A).
//
// The holder satisfies the ADR-0176 C2 readiness-sentinel contract:
//   - Writes /run/podmotion/holder-ready to signal quiescence.
//   - Prints "podmotion-holder ready" to stdout (authoritative signal for scratch rootfs
//     where the sentinel file path may be read-only to non-holder containers).
//   - Never binds any port.
//   - Parks indefinitely and is SIGTERM-clean.
//
// The actual workload command (e.g. redis-server) is restored BY CRIU from the
// checkpoint image — it is never executed by the container runtime; the holder is the
// container init that CRIU restores OVER.
//
// Build: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/holder-linux-amd64 ./cmd/holder/main.go
// The resulting binary is statically linked (CGO_ENABLED=0) and resolves inside a
// FROM-scratch rootfs via the emptyDir mount at /podmotion/holder — no base-image tool dependency.
//
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// sentinelPath is the holder-ready sentinel written to signal quiescence to the
// NRI holder-quiescent barrier (ADR-0195 Rule C / ADR-0176 C2).
// The NRI agent reads this path from inside the container via /proc/<pid>/root or
// observes the stdout token — both are accepted by the barrier.
const sentinelPath = "/run/podmotion/holder-ready"

func main() {
	// Ensure the sentinel directory exists (best-effort; /run/podmotion may be tmpfs-mounted
	// by the agent DaemonSet or already present from a prior run in the same sandbox).
	_ = os.MkdirAll("/run/podmotion", 0700)

	// Write the holder-ready sentinel file.
	if err := os.WriteFile(sentinelPath, []byte("ready\n"), 0644); err != nil {
		// Non-fatal: the barrier also accepts the stdout token.
		fmt.Fprintf(os.Stderr, "holder: warning: could not write sentinel %s: %v\n", sentinelPath, err)
	}

	// Emit the authoritative quiescence token.
	// The NRI barrier (plugin.go) observes this on stdout — guaranteed to be visible
	// before the barrier proceeds because stdout is flushed synchronously here.
	fmt.Println("podmotion-holder ready")

	// Park indefinitely. No busy-loop, no port bind, SIGTERM-clean.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	<-sigCh
	os.Exit(0)
}
