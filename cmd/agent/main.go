/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package main is the PodMotion node agent binary.
// Runs as a DaemonSet on every node. Responsibilities:
//   - On startup: run compatibility probe, create/update NodeMigrationCapacity CR
//   - Periodic heartbeat: update NMC status.lastHeartbeat and status.ready
//   - gRPC server: MigrationAgentService, TransferService, HealthService
//   - NRI plugin: hook into containerd Stopping events for pre-dump trigger
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	log := zap.New().WithName("podmotion-agent")

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Error(nil, "NODE_NAME env var not set")
		os.Exit(1)
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Error(err, "Failed to build in-cluster kubeconfig")
		os.Exit(1)
	}
	_ = cfg

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	log.Info("PodMotion agent starting", "node", nodeName)

	// TODO(M1): run compat prober → create/update NodeMigrationCapacity CR
	// TODO(M1): start gRPC stub server on :9090
	// TODO(M1): start metrics server on :9091
	// TODO(M4): start NRI plugin

	// Heartbeat loop — updates NMC status.lastHeartbeat every 30s
	// Sets status.ready=false on shutdown so scheduler stops sending migrations here
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info("Shutting down — marking node not ready for migration")
				// TODO: patch NMC status.ready=false
				return
			case <-ticker.C:
				// TODO: patch NMC status.lastHeartbeat = now
			}
		}
	}()

	<-ctx.Done()
	log.Info("Agent exiting")
}
