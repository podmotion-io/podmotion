/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

// Package main is the PodMotion node agent binary.
// Runs as a DaemonSet on every node. Responsibilities:
//   - On startup: run compatibility probe, create/update NodeMigrationCapacity CR
//   - Periodic heartbeat: update NMC status.lastHeartbeat and status.ready
//   - gRPC server: MigrationAgentService on :9090 (mTLS via cert-manager in production)
//   - NRI plugin: hook into containerd Stopping events for pre-dump trigger (M5)
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/nri"
	"github.com/podmotion-io/podmotion/internal/agent/server"
	agenttls "github.com/podmotion-io/podmotion/internal/agent/tls"
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

	// Load mTLS config from cert-manager-provisioned secret mount.
	// Falls back to insecure if certs are not present (dev/kind environment).
	tlsCfg, err := agenttls.LoadServerConfig(
		agenttls.DefaultCertFile,
		agenttls.DefaultKeyFile,
		agenttls.DefaultCAFile,
	)
	if err != nil {
		log.Error(err, "Failed to load TLS config")
		os.Exit(1)
	}

	// Select the checkpointer based on OS.
	// On Linux (kind nodes / production), use the real CRIUCheckpointer.
	// On macOS (developer machines), fall back to StubCheckpointer with a warning.
	var checkpointer criu.Checkpointer
	if runtime.GOOS == "linux" {
		log.Info("Using CRIUCheckpointer (real CRIU subprocess via go-criu/v7)")
		checkpointer = criu.NewCRIUCheckpointer("")
	} else {
		log.Info("CRIU not available on this OS — using StubCheckpointer (dev mode)",
			"os", runtime.GOOS)
		checkpointer = &criu.StubCheckpointer{
			SimulatedDirtyMB:          128,
			SimulatedFreezeDurationMs: 150,
		}
	}

	agentSrv := server.New(nodeName, checkpointer)

	// Start gRPC server on :9090.
	go func() {
		if err := agentSrv.ListenAndServe(ctx, ":9090", tlsCfg); err != nil {
			log.Error(err, "gRPC server exited with error")
		}
	}()

	// Start NRI plugin stub. The real pre-dump trigger lands in M5.
	nriPlugin := nri.New(nil)
	go func() {
		if err := nriPlugin.RunStub(ctx); err != nil {
			log.Error(err, "NRI plugin exited with error")
		}
	}()

	// TODO(M1): run compat prober → create/update NodeMigrationCapacity CR
	// TODO(M1): start metrics server on :9091

	// Heartbeat loop — updates NMC status.lastHeartbeat every 30s.
	// Sets status.ready=false on shutdown so the scheduler stops sending migrations here.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info("Shutting down — marking node not ready for migration")
				// TODO(M1): patch NMC status.ready=false
				return
			case <-ticker.C:
				// TODO(M1): patch NMC status.lastHeartbeat = now
			}
		}
	}()

	<-ctx.Done()
	log.Info("Agent exiting")
}
