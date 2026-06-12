# PodMotion

Live pod migration for Kubernetes — the container equivalent of live VM migration.

## Description

PodMotion migrates running pods between nodes with zero downtime, preserving in-memory state via CRIU 4.2 iterative pre-copy, active TCP connections via an eBPF XDP bridge with TCP_REPAIR, and persistent volumes across a multi-tier storage cutover (RWX re-attach, Longhorn dual-engine, Ceph RBD live, snapshot-rsync). It ships as a Kubernetes operator with five CRDs, an out-of-tree scheduler plugin, a custom descheduler plugin, and a per-node gRPC agent.

For full architecture, API reference, and installation guides see [docs/](docs/) or [podmotion.io](https://podmotion.io).

## Getting Started

### Prerequisites
- go version v1.24.6+
- docker version 17.03+.
- kubectl version v1.25+.
- Access to a Kubernetes 1.25+ cluster.
- Linux kernel 5.15+ on all nodes (Ubuntu 22.04 HWE minimum; 6.8+ preferred).
- CRIU 4.x installed on all nodes.
- bpfman DaemonSet deployed on the cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/podmotion:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/podmotion:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create a PodMigration to trigger a live migration:**

```sh
kubectl apply -f config/samples/podmotion_v1alpha1_podmigration.yaml
```

> **NOTE**: The sample manifest requires two fields to be set before applying:
> - `spec.sourcePod` — name of the running pod to migrate (must be in the same namespace)
> - `spec.destinationNode` — name of the target node (must advertise `NodeMigrationCapacity`)
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
make build-installer IMG=<some-registry>/podmotion:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/podmotion/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

Install PodMotion using the included Helm chart:

```sh
helm install podmotion ./charts/podmotion --namespace podmotion-system --create-namespace
```

For available configuration options see the [values reference](charts/podmotion/values.yaml).

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

