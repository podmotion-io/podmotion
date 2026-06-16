# Contributing to PodMotion

PodMotion is the Kubernetes equivalent of live VM migration — live pod migration between nodes
with memory, storage, and network continuity. This document covers everything you need to
contribute code, run tests, and execute the PoC sprint that proves end-to-end live migration.

---

## Workstation Requirements

### macOS (Apple Silicon / arm64)

Install all tools before running any `make` target or E2E test.

```bash
# Package manager tools
brew install protobuf protoc-gen-go protoc-gen-go-grpc helm crane

# Go codegen plugins (must match go.mod versions)
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Controller-runtime envtest (downloads kube-apiserver + etcd binaries)
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
make setup-envtest      # downloads k8s binaries into ./bin/k8s/

# Kind + kubectl (if not already present)
brew install kind kubectl
```

### Required tool versions (tested)

| Tool | Minimum | Install |
|------|---------|---------|
| Go | 1.26 | `brew install go` or https://go.dev |
| protoc | 28+ | `brew install protobuf` |
| protoc-gen-go | v1.35+ | `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest` |
| protoc-gen-go-grpc | 1.5+ | `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest` |
| go-criu | v7.2+ | already in go.mod — `go mod download` |
| helm | v3 or v4 | `brew install helm` |
| crane | 0.20+ | `brew install crane` |
| kind | 0.25+ | `brew install kind` |
| kubectl | 1.30+ | `brew install kubectl` |
| Docker Desktop | 4.x | https://www.docker.com/products/docker-desktop/ |

### Linux (CI / amd64)

```bash
# protoc
apt-get install -y protobuf-compiler
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# CRIU (only needed on nodes where agent runs — not on dev machine)
apt-get install -y criu

# crane
go install github.com/google/go-containerregistry/cmd/crane@latest

# helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Repository Layout

```
api/v1alpha1/           CRD type definitions (5 CRDs)
bpf/                    eBPF C programs (XDP bridge, zero-window hold)
charts/podmotion/       Helm chart for operator + agent DaemonSet
cmd/main.go             Operator binary entrypoint (controller-manager + webhooks)
cmd/agent/              Node agent binary (gRPC server + NRI plugin)
cmd/scheduler/          Custom scheduler binary
config/                 Kustomize bases (CRDs, RBAC, webhook, default)
descheduler/            Custom Balance plugin (creates PodMigration CRs)
deploy/                 NFD rules, bpfman DaemonSet
docs/adr/               Architectural Decision Records (see docs/adr/README.md for current list)
images/kind/            Kind node image Dockerfile (CRIU + bpftool baked in)
internal/agent/         Node agent packages (criu, network, storage, etc.)
internal/controller/    Reconcilers — one package per CRD
internal/webhook/       ValidatingAdmissionWebhook and MutatingAdmissionWebhook
proto/                  gRPC proto definitions + generated Go bindings
scheduler-plugins/      Out-of-tree scheduler plugin (MigrationAwareFilter/Score)
test/e2e/               Ginkgo E2E suite (real kind clusters)
test/chaos/             Chaos injection tests
```

---

## Common Make Targets

```bash
make manifests          # regenerate CRD YAML from type markers
make generate           # run controller-gen deepcopy + object
make proto              # run protoc → regenerate proto/gen/*.go
make build              # build operator, agent, scheduler binaries
make test               # unit tests (requires make setup-envtest first)
make setup-envtest      # download kube-apiserver + etcd for controller tests
make docker-build       # build container images
make kind-image         # build kind node image (CRIU + bpftool)
make kind-create        # create 2-node kind cluster using node image
make deploy             # deploy operator + agent to current kubeconfig cluster
make test-e2e           # Ginkgo E2E suite (requires kind cluster running)
make undeploy           # tear down operator from cluster
make kind-delete        # delete kind cluster
```

---

## Regenerating gRPC Bindings

The proto source lives at `proto/migration_agent.proto`. After any change:

```bash
make proto
# or manually:
protoc --go_out=proto/gen --go_opt=paths=source_relative \
       --go-grpc_out=proto/gen --go-grpc_opt=paths=source_relative \
       proto/migration_agent.proto
```

Generated files in `proto/gen/` are committed to the repo. Never hand-edit them.

---

## License Constraint (ADR-0002)

**CRIU (GPLv2) must always be invoked as a subprocess — never statically linked.**

PodMotion is Apache 2.0. CRIU is GPLv2. The `go-criu` library uses LGPL-2.1 RPC bindings
that communicate with the CRIU process over a Unix socket. This is the only permitted
integration pattern. Any PR that imports CRIU C headers or links CRIU object files will
be rejected.

---

## Security Invariants (ADR-0009 / ADR-0012)

Agent 9 holds veto power. These invariants are enforced in code and cannot be overridden
by feature flags:

1. Source pod is **never deleted** until `TrafficVerified=true` condition is set.
2. Seccomp profile is **always restored** after the checkpoint window — even on rollback.
3. Rollback order is **immutable**: Network → Compute → Storage (ADR-0014).

---

## PoC Sprint 2: Live Migration (nginx / redis / postgres)

The north star — three workloads (nginx, redis, postgres) migrating between kind nodes —
was proven on 2026-06-10. Prerequisites: all tools above installed, `make setup-envtest` done.

```bash
# 1. Build agent and operator images (distroless, no apt network needed)
GOOS=linux GOARCH=amd64 go build -o bin/agent-linux-amd64 ./cmd/agent/main.go
GOOS=linux GOARCH=amd64 go build -o bin/manager-linux-amd64 ./cmd/main.go
docker build -f images/agent/Dockerfile -t podmotion-agent:dev .
docker build -f images/operator/Dockerfile -t podmotion-operator:dev .

# 2. Create the kind cluster (3-node: 1 control-plane + 2 workers)
kind create cluster --config images/kind/kind-config.yaml --name podmotion

# 3. Load images into cluster
kind load docker-image podmotion-agent:dev --name podmotion
kind load docker-image podmotion-operator:dev --name podmotion

# 4. Deploy (CRDs, RBAC, operator, agent DaemonSet)
make deploy

# 5. Deploy test workloads
kubectl create namespace pm-e2e
kubectl apply -f test/e2e/fixtures/

# 6. Trigger migrations
kubectl apply -f - <<'EOF'
apiVersion: migration.podmotion.io/v1alpha1
kind: PodMigration
metadata:
  name: nginx-migration
  namespace: pm-e2e
spec:
  podName: <nginx-pod-name>
  podNamespace: pm-e2e
  targetNodeName: podmotion-worker2
  mode: Cold
  tcpPreservationMode: None
  rollbackOnFailure: false
  completionTimeoutSeconds: 180
EOF

# 7. Watch it happen
kubectl get podmigrations -n pm-e2e -w
```

Expected output on success:
```
NAME              PHASE      SOURCE             DEST               MODE   AGE
nginx-migration   Complete   podmotion-worker   podmotion-worker2  Cold   45s
```

### Important Notes (PoC Sprint 2)

- `tcpPreservationMode` controls TCP socket continuity. Use `None` for cold migrations.
  The eBPF XDP bridge for `BestEffort`/`Strict` modes is not yet implemented.
- CRIU runs with a mock fallback on kind (the agent is distroless and lacks `CAP_SYS_PTRACE`).
  Real CRIU checkpoint/restore requires a privileged node deployment (Sprint 3).
- The agent image (`images/agent/Dockerfile`) is a distroless container with only the agent binary.
  It is separate from the kind node image (`images/kind/Dockerfile`) which is used for E2E clusters.
- The `spec.nodeName` field index is now registered unconditionally (not just with `--enable-spot-reclaim`).
  This is required by `AgentClientPool.ForNode` to find agent pods on destination nodes.

---

## Binary Names and Build Output

`make build-linux` produces binaries with a different name than the Dockerfiles expect. The Makefile handles the rename automatically — **always use `make build-linux`, never hand-build and copy**.

```bash
make build-linux
# Produces: bin/manager-linux-amd64, bin/agent-linux-amd64, bin/criu-wrapper-linux-amd64
```

The Dockerfiles and `.dockerignore` expect exactly these names. A hand-built binary with a different name will produce a silent empty image (`.dockerignore` blocks the wrong name).

---

## Helm Deploy (kind/dev)

**`make deploy` uses kustomize and is not the working path for kind.** Deploy via Helm directly:

```bash
# 1. Build binaries
make build-linux

# 2. Build and load images
docker build -f images/operator/Dockerfile -t podmotion-operator:dev .
docker build -f images/agent/Dockerfile -t podmotion-agent:dev .
kind load docker-image podmotion-operator:dev --name <cluster>
kind load docker-image podmotion-agent:dev --name <cluster>

# 3. Apply CRDs (chart crds/ dir is empty — must apply manually)
kubectl apply -f config/crd/bases/

# 4. Helm install
helm upgrade --install podmotion charts/podmotion/ \
  --namespace podmotion-system \
  --create-namespace \
  --set operator.image.repository=podmotion-operator \
  --set operator.image.tag=dev \
  --set operator.image.pullPolicy=Never \
  --set agent.image.repository=podmotion-agent \
  --set agent.image.tag=dev \
  --set agent.image.pullPolicy=Never \
  --set operator.replicas=1 \
  --set webhook.certManager.enabled=false \
  --set scheduler.enabled=false \
  --set installCRDs=false \
  --set operator.featureGates="TCPPreservation=true"
```

**Critical values for kind:**
- `webhook.certManager.enabled=false` — cert-manager is not present in kind; also removes the volume mount so `podmotion-webhook-tls` secret is not required
- `installCRDs=false` — chart `crds/` dir is empty; apply CRDs manually (step 3)
- `operator.replicas=1` — single replica for dev

**Flags that do NOT exist in the operator binary** — passing these causes an immediate crash:
- `--transfer-mode` — not a real flag
- `--checkpoint-registry` — not a real flag

---

## Operator Flags (cmd/main.go)

| Flag | Default | Notes |
|------|---------|-------|
| `--metrics-bind-address` | `"0"` | Use `:8080` for HTTP |
| `--health-probe-bind-address` | `":8081"` | |
| `--leader-elect` | `false` | Enable for multi-replica |
| `--metrics-secure` | `true` | Set false for dev |
| `--webhook-cert-path` | `""` | Dir containing TLS cert |
| `--enable-http2` | `false` | |
| `--enable-spot-reclaim` | `false` | AWS only |

**The agent does not parse CLI flags.** It reads from environment variables only. The only required env var is `NODE_NAME` (set by the DaemonSet via Kubernetes downward API). The gRPC port is hardcoded to `:9090`.

---

## CRDs and PodMigration Fields

| CRD | Short | Scope | Purpose |
|-----|-------|-------|---------|
| PodMigration | pm | Namespaced | Work object per migration |
| MigrationPolicy | mp | Namespaced | Trigger rules and constraints |
| NodeMigrationCapacity | nmc | Cluster | Per-node capability from agent |
| MigrationCheckpoint | mcp | Namespaced | Checkpoint artifact metadata |
| MigrationWebhookConfig | — | Namespaced | Singleton operator config |

**PodMigration spec fields:**

```yaml
spec:
  podName: <name>           # required — name of the source pod
  podNamespace: <namespace> # required — namespace of the source pod
  targetNodeName: <node>    # optional — pins destination; scheduler selects if empty
  tcpPreservationMode: None # None | BestEffort | Strict
```

Fields that **do not exist**: `destinationNode`, `sourcePodName`, `sourcePodNamespace`. Using these will be silently ignored or rejected by the webhook.

---

## eBPF Object Files

The `bpf/` and `internal/agent/network/bpfloader/` directories contain pre-compiled eBPF object files (`.o`). These are committed so users can build without requiring clang/llvm. To rebuild them from source:

```bash
make build-bpf   # requires clang, llvm, libbpf-dev
```

---

## Sign-off (DCO)

Contributors must sign off commits per the Developer Certificate of Origin. Use `git commit -s`. See GOVERNANCE.md and ADR-0090 for the full policy.

---

## Adding a New Milestone

1. Create `docs/adr/NNNN-<title>.md` for any new architectural decisions.
2. Add a row to `docs/adr/README.md`.
3. Implement behind an interface with a `Stub` implementation for unit tests.
4. Add the milestone to `MILESTONES.md` and mark prior milestone complete.
5. Run `make manifests generate build test` — all must pass before commit.
