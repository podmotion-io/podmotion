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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
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
	// Wire the controller-runtime global logger so packages that use ctrl.Log / logf.Log
	// (e.g. internal/agent/server, internal/agent/nri) produce structured output instead
	// of panicking with "log.SetLogger(...) was never called".
	ctrl.SetLogger(log)

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

	// Build a controller-runtime cluster so the agent has a cached, informer-backed k8s client.
	// The cache is required for the ADR-0118 podUID-from-CR fallback: Checkpoint reads the
	// PodMigration CR, and a cold (un-synced) cache would return spurious not-found errors.
	var k8sClient client.Client
	cl, clErr := cluster.New(cfg, func(o *cluster.Options) { o.Scheme = scheme })
	if clErr != nil {
		log.Error(clErr, "Failed to build k8s cluster client — MigrationCheckpoint CR updates will be skipped")
		k8sClient = nil
	} else {
		k8sClient = cl.GetClient()
		// Run the cluster (starts the informer cache) for the agent's lifetime.
		go func() {
			if err := cl.Start(ctx); err != nil {
				log.Error(err, "cluster cache runtime exited with error")
			}
		}()
	}

	agentSrv := server.New(nodeName, checkpointer, k8sClient)

	// Start gRPC server on :9090.
	go func() {
		// ADR-0118 Blocking Item 1: do not accept Checkpoint RPCs until the informer cache
		// has completed its initial sync, otherwise CR lookups race against cache warm-up.
		if cl != nil {
			if ok := cl.GetCache().WaitForCacheSync(ctx); !ok {
				log.Error(nil, "informer cache failed to sync — refusing to start gRPC server")
				os.Exit(1)
			}
		}
		if err := agentSrv.ListenAndServe(ctx, ":9090", tlsCfg); err != nil {
			log.Error(err, "gRPC server exited with error")
		}
	}()

	// Start NRI plugin. OnStartContainer triggers CRIU restore when a replacement pod
	// bearing podmotion.io/checkpoint-ref starts on this node (North Star #2 path).
	nriPlugin := nri.New(
		nil, // OnStopping: pre-dump trigger wired in M5
		func(ctx context.Context, event nri.ContainerEvent, checkpointRef string) error {
			// checkpointRef is already validated by HandleStartContainer regex before
			// this callback is invoked, so concatenation is safe here.
			checkpointDir := "/run/podmotion/checkpoints/" + checkpointRef + "/final"
			log.Info("NRI StartContainer: invoking CRIU restore",
				"container", event.ID,
				"pod", event.Pod,
				"checkpointRef", checkpointRef,
				"checkpointDir", checkpointDir,
			)
			// ADR-0122: pass the replacement pod's containerd sandbox ID (pod.GetId()) so
			// JoinNsRestore can resolve its netns via the containerd sandbox API and hand the
			// open fd to CRIU via --net-fd.
			pid, err := agentSrv.JoinNsRestore(checkpointRef, checkpointDir, event.SandboxID)
			if err != nil {
				log.Error(err, "NRI CRIU restore failed", "container", event.ID)
				return err
			}
			log.Info("NRI CRIU restore complete", "container", event.ID, "restoredPID", pid)

			// ADR-0120 D3: propagate authoritative restore confirmation back to the
			// PodMigration CR. The migration name equals the checkpoint-ref; the CR
			// namespace is carried on the replacement pod via podmotion.io/migration-namespace.
			migrationNamespace := event.Annotations["podmotion.io/migration-namespace"]
			if migrationNamespace == "" {
				migrationNamespace = event.Namespace // fall back to the pod's namespace
			}
			// Use a fresh context: the NRI handler context (ctx) is cancelled
			// when the NRI socket disconnects during CRIU restore, which would
			// cause the k8s patch to hit "context deadline exceeded".
			reportCtx, reportCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer reportCancel()
			// ADR-0133 D3: collect the replacement pod's eth0 MAC inside the restored
			// process's netns so the operator can install the destination IP handoff for
			// the OLD pod IP. Best-effort: log on failure, the operator has a fallback.
			// Resolve the sandbox netns path (the join-ns restore target) as the authoritative
			// source for eth0's MAC; the restored PID's netns can transiently lack eth0 and the
			// `ctr containers info` lookup can race the post-restore settle. Retry both briefly.
			var replVethMAC string
			var macErr error
			for attempt := 0; attempt < 6; attempt++ {
				// Prefer the exact netns path CRIU joined (stashed by joinNsRestore); fall back
				// to resolving it from the sandbox spec. Both can lag the post-restore settle,
				// so retry briefly.
				netnsPath := agentSrv.ResolvedNetnsPath(checkpointRef)
				if netnsPath == "" {
					if p, nsErr := agentSrv.SandboxNetnsPath(reportCtx, event.SandboxID); nsErr == nil {
						netnsPath = p
					} else {
						log.Info("NRI CRIU restore: SandboxNetnsPath lookup retrying (ADR-0133)",
							"attempt", attempt, "err", nsErr.Error())
					}
				}
				replVethMAC, macErr = server.ReadReplVethMAC(pid, netnsPath)
				if macErr == nil && replVethMAC != "" {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if macErr != nil {
				log.Error(macErr, "NRI CRIU restore: could not read replacement pod eth0 MAC (ADR-0133) — operator will fall back to diagnostic exec",
					"migration", checkpointRef, "restoredPID", pid)
			} else {
				log.Info("NRI CRIU restore: collected replacement pod eth0 MAC (ADR-0133)",
					"migration", checkpointRef, "replVethMAC", replVethMAC)
			}
			if err := agentSrv.ReportRestoreConfirmed(reportCtx, checkpointRef, migrationNamespace, int32(pid), replVethMAC); err != nil {
				log.Error(err, "NRI CRIU restore: failed to report confirmation to CR — controller poll will time out",
					"migration", checkpointRef, "namespace", migrationNamespace)
				return err
			}
			return nil
		},
	).WithK8sVerification(k8sClient, nodeName)
	go func() {
		if err := nriPlugin.Run(ctx); err != nil {
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

	// TODO(podmotion-io/podmotion#<issue>, M1): start metrics server on :9091 (Prometheus /metrics endpoint for agent DaemonSet scraping).

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
