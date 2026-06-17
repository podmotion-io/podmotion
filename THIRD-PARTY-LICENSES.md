# Third-Party Licenses

PodMotion is licensed under the **Apache License 2.0** (see `LICENSE`).

This document records the licenses of third-party Go modules that PodMotion
depends on, and the compliance basis for any non-permissive (copyleft) license
in the dependency graph. It is maintained per **ADR-0077 §6** and is checked in
CI by a `go-licenses` scan that FAILS if any LGPL or GPL package is added
without a corresponding entry below.

> **CRIU itself is NOT a dependency listed here.** CRIU (GPLv2) is invoked as a
> system **subprocess** over its RPC socket — never statically linked into any
> PodMotion binary (ADR-0002). Only the Go *bindings* to CRIU's RPC protocol
> (`go-criu`, LGPL-2.1) are compiled in; see the dedicated section below.

---

## Copyleft dependencies — explicit compliance basis

### github.com/checkpoint-restore/go-criu/v7

- **Version:** v7.2.0 (pinned in `go.mod`)
- **License:** LGPL-2.1-only
- **Usage:** Go package import — CRIU RPC protocol client and generated
  protobuf RPC types. Imported at
  `internal/agent/criu/criu_checkpointer.go` for checkpoint/restore
  orchestration over the CRIU RPC Unix-domain socket.
- **Relinking:** Users may substitute a modified version of go-criu by adding a
  `replace` directive in `go.mod` and recompiling from source. See `BUILDING.md`.
- **LGPL compliance basis:** LGPL-2.1 §6(b) — relinkability via the open Go
  toolchain satisfies the "suitable shared library mechanism" requirement. The
  binary is not distributed with a sealed or proprietary build system, so a user
  can always relink against a modified go-criu. (ADR-0077 §6.)

No other LGPL or GPL module is present in the PodMotion dependency graph. If one
is added, this section must gain a corresponding entry in the same commit, or
the `go-licenses` CI check fails.

---

## Direct dependencies (top-level `require`, `go.mod`)

All modules below are permissively licensed (Apache-2.0, BSD-3-Clause,
BSD-2-Clause, or MIT) except the LGPL-2.1 go-criu binding documented above.

| Module | Version | License |
|--------|---------|---------|
| github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 | v1.55.4 | Apache-2.0 |
| github.com/checkpoint-restore/go-criu/v7 | v7.2.0 | **LGPL-2.1-only** (see above) |
| github.com/cilium/ebpf | v0.21.0 | MIT / BSD-2-Clause (dual) |
| github.com/containerd/nri | v0.12.0 | Apache-2.0 |
| github.com/onsi/ginkgo/v2 | v2.27.2 | MIT |
| github.com/onsi/gomega | v1.38.2 | MIT |
| github.com/prometheus/client_golang | v1.23.2 | Apache-2.0 |
| go.uber.org/zap | v1.27.0 | MIT |
| google.golang.org/grpc | v1.72.2 | Apache-2.0 |
| google.golang.org/protobuf | v1.36.8 | BSD-3-Clause |
| k8s.io/api | v0.35.0 | Apache-2.0 |
| k8s.io/apimachinery | v0.35.0 | Apache-2.0 |
| k8s.io/client-go | v0.35.0 | Apache-2.0 |
| k8s.io/component-base | v0.35.0 | Apache-2.0 |
| k8s.io/klog/v2 | v2.130.1 | Apache-2.0 |
| sigs.k8s.io/controller-runtime | v0.23.3 | Apache-2.0 |

## Notable indirect dependencies

| Module | License |
|--------|---------|
| github.com/aws/aws-sdk-go-v2 (and submodules) | Apache-2.0 |
| github.com/aws/smithy-go | Apache-2.0 |
| github.com/containerd/log, github.com/containerd/ttrpc | Apache-2.0 |
| github.com/opencontainers/runtime-spec | Apache-2.0 |
| github.com/sirupsen/logrus | MIT |
| github.com/tetratelabs/wazero | Apache-2.0 |
| github.com/google/cel-go, cel.dev/expr | Apache-2.0 |
| github.com/google/go-cmp, github.com/google/uuid | BSD-3-Clause |
| github.com/spf13/cobra, github.com/spf13/pflag | Apache-2.0 / BSD-3-Clause |
| github.com/davecgh/go-spew | ISC |
| github.com/json-iterator/go, github.com/modern-go/* | MIT |
| go.opentelemetry.io/otel (and submodules) | Apache-2.0 |
| go.uber.org/multierr | MIT |
| golang.org/x/* (net, sys, text, sync, mod, tools, oauth2, term, time, exp) | BSD-3-Clause |
| google.golang.org/genproto/* | Apache-2.0 |
| gopkg.in/yaml.v3, go.yaml.in/yaml/* | MIT / Apache-2.0 |
| sigs.k8s.io/json, sigs.k8s.io/yaml, sigs.k8s.io/structured-merge-diff/v6 | Apache-2.0 / BSD-3-Clause |
| k8s.io/* (apiextensions-apiserver, apiserver, kube-openapi, utils) | Apache-2.0 |

---

## Regenerating / verifying this file

The authoritative, machine-generated license inventory is produced by
`go-licenses`:

```bash
go install github.com/google/go-licenses@latest
go-licenses report ./... > /tmp/podmotion-licenses.csv
# Confirm no forbidden (GPL/AGPL) license and that every LGPL entry is
# documented in the "Copyleft dependencies" section above.
go-licenses check ./... --disallowed_types=forbidden
```

The full, version-exact dependency set is always `go.mod` / `go.sum`. This
document is the human-readable compliance summary required by ADR-0077 §6;
the CI `go-licenses` scan is the enforcement mechanism.
