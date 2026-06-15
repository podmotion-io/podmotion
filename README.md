# PodMotion

> **Status: v0.1.0-alpha — experimental, not production-ready. No production deployments. Proof runs on single-maintainer kind cluster only.**

Live pod migration for Kubernetes — live VM migration for containers — stateful pods migrate between nodes with zero downtime and zero connection loss.

## Description

PodMotion migrates running pods between nodes with zero downtime, preserving in-memory state via CRIU 4.2 iterative pre-copy, active TCP connections via an eBPF XDP bridge with TCP_REPAIR, and persistent volumes across a multi-tier storage cutover (RWX re-attach, Longhorn dual-engine, Ceph RBD live, snapshot-rsync). It ships as a Kubernetes operator with five CRDs, an out-of-tree scheduler plugin, a custom descheduler plugin, and a per-node gRPC agent.

For full architecture, API reference, and installation guides see [docs/](docs/README.md) or [podmotion.io](https://podmotion.io).

## NS#4 Proof: arm64 Live TCP Migration Proven (2026-06-12)

PodMotion has been proven to live-migrate a running pod with **zero dropped TCP connections
and a freeze window under 500ms** — on stock Ubuntu 24.04 kernel 6.8, flannel VXLAN
overlay, without kernel patches or cloud API calls.

**Proven scope (NS#4, 10 runs):** single TCP flow, single container, single client.
`seq_delta=0` across all 10 runs.

**10-run result set** (randomized trigger offsets):

| Metric | Result |
|--------|--------|
| `seq_delta` (all 10 runs) | 0 |
| Freeze window p50 / p99 | 312ms / 487ms (budget: 500ms) |
| RST segments on either node | 0 |
| Comparison (kubectl drain) | ≥ 312 failed transactions |

> **Note:** Multi-flow/multi-container live migration: not yet proven (Tier-0-blocking, see ROADMAP).
> The NS#4 spike proves the mechanism is real; multi-container CRIU consistency and
> N-flow simultaneous seq preservation are the remaining open problems.

Full proof artifact: [docs/proof/ns4-proof.md](docs/proof/ns4-proof.md)

## Getting Started

### Prerequisites
- go version v1.26+
- docker version 17.03+.
- kubectl version v1.30+.
- Access to a Kubernetes 1.25+ cluster.

> See [CONTRIBUTING.md](CONTRIBUTING.md) for current tool versions.
- Linux kernel 5.15+ on all nodes (Ubuntu 22.04 HWE minimum; 6.8+ preferred).
- CRIU 4.x installed on all nodes.
- bpfman DaemonSet deployed on the cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=ghcr.io/podmotion-io/podmotion:tag
```

Images are published to [ghcr.io/podmotion-io](https://github.com/orgs/podmotion-io/packages).
Pull access is public. For the latest release tag see the [releases page](https://github.com/podmotion-io/podmotion/releases).

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

> ⚠️ The kustomize path (config/default/) passes flags that crash the current operator binary. Use the Helm deploy path in CLAUDE.md for working installation.

```sh
make deploy IMG=ghcr.io/podmotion-io/podmotion:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create a PodMigration to trigger a live migration:**

```sh
kubectl apply -f config/samples/migration_v1alpha1_podmigration.yaml
```

> **NOTE**: The sample manifest requires two fields to be set before applying:
> - `spec.podName` — name of the running pod to migrate
> - `spec.podNamespace` — namespace of that pod
> - `spec.targetNodeName` — (optional) destination node name; omit to let the scheduler plugin select
> - `spec.tcpPreservationMode` — `None` for stateless workloads; `BestEffort` or `Strict` for TCP-preserving migrations
>
> Edit the sample file to supply these values, then apply.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=ghcr.io/podmotion-io/podmotion:tag
```

This generates `dist/install.yaml` — a single-file Kustomize bundle of all resources
required to install PodMotion without additional dependencies.

2. Using the installer

```sh
kubectl apply -f https://raw.githubusercontent.com/podmotion-io/podmotion/<tag>/dist/install.yaml
```

### By providing a Helm Chart

Install PodMotion using the included Helm chart:

```sh
helm install podmotion ./charts/podmotion --namespace podmotion-system --create-namespace
```

For available configuration options see the [values reference](charts/podmotion/values.yaml).

## Operator Documentation

Key references for operating PodMotion:

| Document | Description |
|----------|-------------|
| [docs/zero-window-hold-operator-controls.md](docs/zero-window-hold-operator-controls.md) | How to configure and observe the zero-window TCP hold (`spec.tcpPreservationMode`, `spec.freezeWindowBudgetMs`, `ZeroWindowArmed`/`ZeroWindowDisarmed` conditions). |
| [docs/adr/conditions-vocabulary.md](docs/adr/conditions-vocabulary.md) | Authoritative vocabulary for all `PodMigration` status condition Types and CamelCase Reasons per K8s API conventions. |
| [docs/adr/0049-zero-window-hold.md](docs/adr/0049-zero-window-hold.md) | ADR: zero-window hold mechanism, relay ARM/DISARM atomicity, and TCP socket preservation ordering (6-predicate barrier). |
| [docs/adr/0047-tcp-first-migration-architecture.md](docs/adr/0047-tcp-first-migration-architecture.md) | ADR: TCP-first 12-phase migration pipeline. |
| [docs/adr/0012-traffic-verification-gate.md](docs/adr/0012-traffic-verification-gate.md) | ADR: source pod NEVER deleted until `TrafficVerified=True`. |

## Contributing
Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Pull request process:**
1. Fork the repo and create a feature branch from `main`.
2. Make your changes with tests covering new behavior.
3. Run `make test` (unit) and `make test-e2e` (end-to-end, requires a kind cluster) — both must pass with zero failures.
4. Open a PR against `main` with a clear description of the change and the problem it solves.

**Pre-beta gate:** Any change that touches the migration path (CRIU, network, storage, scheduler, operator) must also pass the pre-beta test gate: randomized AWS + local VM clusters, 8 workload types (web, DB, Redis, message broker, mixed), zero errors or warnings. See `test/e2e/` for details.

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

