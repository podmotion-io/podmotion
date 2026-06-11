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

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	"github.com/podmotion-io/podmotion/internal/agent/nmcregistrar"
	"github.com/podmotion-io/podmotion/internal/agent/nri"
	"github.com/podmotion-io/podmotion/internal/agent/server"
	agenttls "github.com/podmotion-io/podmotion/internal/agent/tls"
)

var scheme = k8sruntime.NewScheme()

func init() {
	utilruntime.Must(pmv1.AddToScheme(scheme))
}

func main() {
	log := zap.New().WithName("podmotion-agent")

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Error(nil, "NODE_NAME env var not set")
		os.Exit(1)
	}

	// Try in-cluster config first (DaemonSet pod), fall back to kubeconfig file
	// (bare binary on VM for PoC sprints).
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = "/etc/rancher/k3s/k3s.yaml" // k3s default
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Error(err, "Failed to build kubeconfig (tried in-cluster and file)")
			os.Exit(1)
		}
		log.Info("Using kubeconfig file", "path", kubeconfig)
	}

	registrar, regErr := nmcregistrar.New(cfg, nodeName)
	if regErr != nil {
		log.Error(regErr, "Failed to build NMC registrar — NMC registration will be skipped")
		registrar = nil
	}

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
		checkpointer = criu.NewCRIUCheckpointer("/usr/local/sbin/criu")
	} else {
		log.Info("CRIU not available on this OS — using StubCheckpointer (dev mode)",
			"os", runtime.GOOS)
		checkpointer = &criu.StubCheckpointer{
			SimulatedDirtyMB:          128,
			SimulatedFreezeDurationMs: 150,
		}
	}

	// Build a k8s client so the agent can upsert MigrationCheckpoint CRs.
	var k8sClient client.Client
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "Failed to build k8s client — MigrationCheckpoint CR updates will be skipped")
		k8sClient = nil
	}

	agentSrv := server.New(nodeName, checkpointer, k8sClient)

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

	// Register NodeMigrationCapacity for this node.
	// Non-fatal: agent still serves gRPC even if NMC registration fails temporarily.
	if registrar != nil {
		if err := registrar.Register(ctx); err != nil {
			log.Error(err, "NMC registration failed — will retry via heartbeat")
		} else {
			log.Info("NodeMigrationCapacity registered", "node", nodeName)
		}
	}

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
				if registrar != nil {
					if err := registrar.Deregister(context.Background()); err != nil {
						log.Error(err, "Failed to deregister NMC on shutdown")
					}
				}
				return
			case <-ticker.C:
				if registrar != nil {
					if err := registrar.Heartbeat(ctx); err != nil {
						log.Error(err, "NMC heartbeat failed")
					}
				}
			}
		}
	}()

	<-ctx.Done()
	log.Info("Agent exiting")
}
