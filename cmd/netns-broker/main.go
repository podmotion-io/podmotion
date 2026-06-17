/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Command netns-broker is the SD-1-NETNS-BROKER privileged sidecar
// (ADR-0148 Amendment SD-1-NETNS-BROKER).
//
// It runs as the SOLE privileged:true container in the agent DaemonSet pod and
// does ONLY two things: create and tear down per-migration network-namespace
// bind-mounts in the HOST mount namespace, over a root-only Unix domain socket
// (/run/podmotion/netns-broker.sock, mode 0600). It speaks no gRPC. The bind
// privilege (CAP_SYS_ADMIN host-mount-ns mount/umount2) is irreducible because
// CRIU must open the netns path from the host mount namespace via --join-ns
// net:<path>; SD-1 isolates it here instead of in the long-lived main agent,
// which is de-privileged (privileged:false) as a result.
//
// This binary is identical in behavior to invoking the agent image with
// `args: ["netns-broker"]` (cmd/agent/main.go subcommand dispatch) — both call
// netnsbroker.Serve. The standalone binary exists so the broker can also be
// shipped as its own minimal image if a future ADR splits the images.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
)

func main() {
	log := zap.New().WithName("netns-broker")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := netnsbroker.Run(ctx, log); err != nil {
		log.Error(err, "netns-broker exited with error")
		os.Exit(1)
	}
}
