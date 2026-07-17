/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"k8s.io/client-go/dynamic"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	migrationv1alpha1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	agentclient "github.com/podmotion-io/podmotion/internal/agent/client"
	"github.com/podmotion-io/podmotion/internal/agent/replication"
	"github.com/podmotion-io/podmotion/internal/agent/storage"
	agenttls "github.com/podmotion-io/podmotion/internal/agent/tls"
	"github.com/podmotion-io/podmotion/internal/agent/traffic"
	"github.com/podmotion-io/podmotion/internal/buildinfo"
	"github.com/podmotion-io/podmotion/internal/controller"
	"github.com/podmotion-io/podmotion/internal/controller/spotreclaim"
	"github.com/podmotion-io/podmotion/internal/estimation"
	"github.com/podmotion-io/podmotion/internal/featuregate"
	"github.com/podmotion-io/podmotion/internal/rollback"
	pmwebhook "github.com/podmotion-io/podmotion/internal/webhook"
	corev1 "k8s.io/api/core/v1"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(migrationv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var enableSpotReclaim bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(&enableSpotReclaim, "enable-spot-reclaim", false,
		"If set, the SpotReclaimReconciler is started. Enable only on AWS clusters with spot instances.")
	var featureGates string
	flag.StringVar(&featureGates, "feature-gates", "",
		"Comma-separated list of <Gate>=true|false pairs enabling experimental features "+
			"(e.g. TCPPreservation=true,GPUMigration=false). No gate is enabled by default.")
	var longhornManagerURL string
	flag.StringVar(&longhornManagerURL, "longhorn-manager-url", "http://longhorn-backend.longhorn-system.svc.cluster.local:9500",
		"Base URL of the Longhorn Manager HTTP API, used by the Tier1 (Longhorn) storage "+
			"migrator for dual-engine replica add/poll/detach/attach during live migration. "+
			"Defaults to the standard in-cluster Longhorn service address; override for "+
			"non-standard Longhorn installs (different namespace/service name) or out-of-cluster "+
			"testing.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Apply experimental feature gates from --feature-gates before any reconciler
	// or webhook consults featuregate.IsEnabled. Without this, gates such as
	// TCPPreservation can never be enabled at runtime and the admission webhook
	// hard-blocks every TCPPreservationMode=Strict/BestEffort migration.
	if err := featuregate.ParseFlags(featureGates); err != nil {
		setupLog.Error(err, "invalid --feature-gates")
		os.Exit(1)
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// ADR-0222: gate webhook server construction on the presence of a serving cert.
	// controller-runtime adds a webhook runnable that reads tls.crt at startup; under
	// certManager.enabled=false no cert is provided, so building the server unconditionally
	// crashes the operator (CrashLoopBackOff) before leader election. One decision variable
	// drives both server construction (Gate A) and handler registration (Gate B).
	webhooksEnabled := len(webhookCertPath) > 0

	// Gate A: build the webhook server and wire ctrl.Options.WebhookServer ONLY when a cert
	// is present. Leave it nil otherwise so controller-runtime registers no webhook runnable.
	var webhookServer webhook.Server
	if webhooksEnabled {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions := webhook.Options{
			TLSOpts:  tlsOpts,
			CertDir:  webhookCertPath,
			CertName: webhookCertName,
			KeyName:  webhookCertKey,
		}
		webhookServer = webhook.NewServer(webhookServerOptions)
	} else {
		setupLog.Info("webhook server disabled (no --webhook-cert-path); admission webhooks not registered")
	}

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "c2700499.podmotion.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// Build mTLS client config for operator→agent calls.
	// Falls back to insecure when certs are absent (dev/kind environment).
	// ADR-SEC-C (GC-B7): the operator verifies the agent peer by SPIFFE identity (custom
	// VerifyPeerCertificate), pinning spiffe://podmotion.io/ns/<ns>/sa/podmotion-agent. The
	// namespace is read from POD_NAMESPACE (downward API, deployment.yaml) — NOT hardcoded — so a
	// non-default-namespace install pins the correct agent identity (M2).
	operatorNamespace := os.Getenv("POD_NAMESPACE")
	if operatorNamespace == "" {
		operatorNamespace = "podmotion-system"
		setupLog.Info("POD_NAMESPACE unset; defaulting operator namespace for agent SPIFFE pin (ADR-SEC-C M2)", "namespace", operatorNamespace)
	}
	agentTLSCfg, err := agenttls.LoadClientConfig(
		agenttls.DefaultCertFile,
		agenttls.DefaultKeyFile,
		agenttls.DefaultCAFile,
		operatorNamespace,
	)
	if err != nil {
		setupLog.Error(err, "Failed to load agent client TLS config")
		os.Exit(1)
	}
	agentPool := agentclient.NewAgentClientPool(mgr.GetClient(), "9090", agentTLSCfg)

	// Register the spec.nodeName field index unconditionally — required by AgentClientPool.ForNode
	// to efficiently list agent pods on a specific node without a full cache scan.
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&corev1.Pod{},
		spotreclaim.NodeFieldIndexName,
		spotreclaim.PodNodeNameIndexer,
	); err != nil {
		setupLog.Error(err, "Failed to register pod nodeName field index")
		os.Exit(1)
	}

	// AWSLBStubVerifier is used until a real AWS cluster is available (M9 live PoC).
	// Replace with AWSLoadBalancerVerifier + TargetGroupDiscovery when running on AWS.
	compositeVerifier := &traffic.CompositeVerifier{
		EndpointSliceVerifier: &traffic.StubVerifier{},
		AWSALBVerifier:        &traffic.AWSLBStubVerifier{},
	}

	// Wire ReplicationMgr and StorageMgr so the PreMigrating state machine can advance.
	// ReplicationManager drives the pre-copy dirty-page sync loop (sets MemorySynced=True).
	// StorageMigrationManager drives storage pre-stage (sets StorageReadyForFreeze=True).
	replicationMgr := &replication.ReplicationManager{Client: mgr.GetClient(), AgentPool: agentPool}
	storageMgr := storage.NewStorageMigrationManager(mgr.GetClient())
	// Wire the real Longhorn Tier1 migrator (dual-engine replica add/poll/detach/attach via
	// the Longhorn Manager HTTP API) in place of the LonghornStubMigrator default. Without
	// this, TierLonghorn always reports 100% sync on the first poll and the freeze proceeds
	// before a destination replica has actually been created — silent data loss on any
	// Longhorn-backed volume. Ceph RBD and SnapshotRsync stay on their stub defaults here;
	// this sprint's live testing only exercised and confirmed the Longhorn path.
	storageMgr.RegisterMigrator(storage.TierLonghorn, storage.NewLonghornMigrator(longhornManagerURL))

	// ADR-0322: dynamic client for the Cilium CiliumEndpoint readiness poll
	// (cilium.io/v2 is a CRD, not compiled into the typed clientset).
	dynamicClient, err := dynamic.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create dynamic client for Cilium CiliumEndpoint polling (ADR-0322)")
		os.Exit(1)
	}

	// Typed clientset threaded into CNIMobilitySelector for handoff strategies that need it —
	// currently CalicoHandoff.WaitForWorkloadEndpointReady polls the destination pod via the
	// typed Pods().Get API (calico.go).
	kubeClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create typed kubernetes client for CNIMobilitySelector")
		os.Exit(1)
	}

	if err := (&controller.PodMigrationReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		DynamicClient: dynamicClient,
		KubeClient:    kubeClient,
		Estimator: &estimation.DefaultEstimator{
			Prober: &estimation.StubProber{},
		},
		// ADR-0248 D2: wire a real source-agent client so a mid-checkpoint abort's
		// rollback pipeline drives the source-agent Abort RPC directly (reaching
		// thawFrozenSource) on the live (non-restart) path, instead of relying solely
		// on an agent restart (ReconcileOrphanedFrozenSources) or a coincidental
		// independent Abort caller. The adapter resolves the migration's source node
		// (Status.SourceNodeName) and dispatches Abort via the same AgentPool used for
		// the destination agent. There is no freeze-deadline watchdog; this is the
		// controller-driven thaw path.
		Rollbacker: rollback.NewStubRollbacker(
			agentclient.NewSourceRollbackClient(agentPool, mgr.GetClient()),
		),
		AgentPool:       agentPool,
		TrafficVerifier: compositeVerifier,
		ReplicationMgr:  replicationMgr,
		StorageMgr:      storageMgr,
		Recorder:        mgr.GetEventRecorderFor("podmigration-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "podmigration")
		os.Exit(1)
	}
	if err := (&controller.MigrationPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "migrationpolicy")
		os.Exit(1)
	}
	if err := (&controller.NodeMigrationCapacityReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "nodemigrationcapacity")
		os.Exit(1)
	}
	if err := (&controller.MigrationCheckpointReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "migrationcheckpoint")
		os.Exit(1)
	}
	if err := (&controller.MigrationWebhookConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "migrationwebhookconfig")
		os.Exit(1)
	}
	// Gate B (ADR-0222): register admission webhook handlers ONLY when the webhook server
	// was built (webhooksEnabled). Registering handlers when WebhookServer is nil forces
	// controller-runtime to add the webhook runnable that reads tls.crt and crashes.
	if webhooksEnabled {
		if err := (&pmwebhook.EvictionInterceptor{}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to register webhook", "webhook", "EvictionInterceptor")
			os.Exit(1)
		}
		if err := (&pmwebhook.PodMigrationValidator{}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to register webhook", "webhook", "PodMigrationValidator")
			os.Exit(1)
		}
		if err := (&pmwebhook.PodMigrationDefaulter{}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to register webhook", "webhook", "PodMigrationDefaulter")
			os.Exit(1)
		}
		if err := pmwebhook.NewPodMutatingWebhook(mgr.GetClient(), mgr.GetScheme()).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to register webhook", "webhook", "PodMutatingWebhook")
			os.Exit(1)
		}
		// ADR-0039 SD-6 / ADR-0148: block exec/attach/ephemeralcontainers into
		// privileged podmotion-agent pods (and nodes/proxy from the agent SA).
		if err := (&pmwebhook.AgentExecBlockWebhook{}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to register webhook", "webhook", "AgentExecBlockWebhook")
			os.Exit(1)
		}
	} else {
		setupLog.Info("admission webhooks not registered (webhook server disabled)")
	}
	if enableSpotReclaim {
		if err := (&spotreclaim.SpotReclaimReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to create controller", "controller", "spotreclaim")
			os.Exit(1)
		}
		setupLog.Info("SpotReclaimReconciler enabled")
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	// Surface the authoritative build identity so a live-migration proof run can be
	// bound to the exact source tree this binary was built from, instead of inferring
	// artifact/source correspondence structurally after the fact. A dirty build is
	// flagged explicitly: its identity is not pinned to a commit.
	prov := buildinfo.Read()
	setupLog.Info("build provenance", prov.LogValues()...)
	if prov.Dirty {
		setupLog.Info("WARNING: operator built from a working tree with uncommitted changes — build identity is NOT pinned to a commit; a proof artifact must record this and be rebuilt from a committed tree to establish artifact/source correspondence")
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
