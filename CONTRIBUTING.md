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
cmd/operator/           Operator binary (controller-manager + webhooks)
cmd/agent/              Node agent binary (gRPC server + NRI plugin)
cmd/scheduler/          Custom scheduler binary
config/                 Kustomize bases (CRDs, RBAC, webhook, default)
descheduler/            Custom Balance plugin (creates PodMigration CRs)
deploy/                 NFD rules, bpfman DaemonSet
docs/adr/               Architectural Decision Records (35 ADRs)
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

## PoC Sprint: First Live Migration

The north star is a running nginx pod migrating live between two kind nodes.
Prerequisites: all tools above installed, `make setup-envtest` done.

```bash
# 1. Build the kind node image (CRIU + bpftool baked in)
make kind-image

# 2. Create a 2-node kind cluster
make kind-create

# 3. Build and deploy operator + agent
make docker-build
make deploy

# 4. Trigger a cold migration
kubectl apply -f test/e2e/fixtures/nginx.yaml
kubectl-podmotion migrate nginx-deployment-<pod> --target-node kind-worker2 --mode=Cold --wait

# 5. Watch it happen
kubectl get podmigrations -w
```

Expected output on success:
```
NAME                    PHASE       AGE
nginx-cold-migration    Complete    45s
```

---

## Adding a New Milestone

1. Create `docs/adr/NNNN-<title>.md` for any new architectural decisions.
2. Add a row to `docs/adr/README.md`.
3. Implement behind an interface with a `Stub` implementation for unit tests.
4. Add the milestone to `MILESTONES.md` and mark prior milestone complete.
5. Run `make manifests generate build test` — all must pass before commit.
