# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/podmotion-io/podmotion:latest
# YEAR defines the year value used for substituting the YEAR placeholder in the boilerplate header.
YEAR ?= $(shell date +%Y)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: proto
proto: ## Generate Go bindings from proto/migration_agent.proto using protoc.
	PATH=$(PATH):$(GOBIN) protoc \
		--go_out=proto/gen \
		--go_opt=paths=source_relative \
		--go-grpc_out=proto/gen \
		--go-grpc_opt=paths=source_relative \
		-I proto \
		proto/migration_agent.proto

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen bpf-generate ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths="./..."

# bpf-generate requires clang and libbpf-dev on the build host (apt-get install clang libbpf-dev).
# Also requires github.com/cilium/ebpf in go.mod: run `go get github.com/cilium/ebpf@latest` first.
GO ?= go
.PHONY: bpf-generate
bpf-generate: ## Generate Go bindings for BPF C programs via bpf2go
	$(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-target amd64 \
		-output-dir internal/agent/network/bpf \
		ZeroWindow bpf/zero_window.c -- \
		-I/usr/include/linux -I/usr/include
	$(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-target amd64 \
		-output-dir internal/agent/network/bpf \
		XDPBridge bpf/xdp_bridge.c -- \
		-I/usr/include/linux -I/usr/include

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# E2E tests target the STANDING KVM/libvirt kubeadm cluster (VMs pm-cp1/pm-w1/pm-w2 on
# the libvirt `default` NAT network, 192.168.122.0/24). Node IPs are DHCP — do NOT
# hardcode them; discover via `sudo virsh net-dhcp-leases default` or the CP1/W1/W2
# vars in $(HOME)/podmotion-kvm/hosts.env. Kind cluster creation is intentionally
# skipped. The cluster must be reachable via KUBECONFIG (default below points at the
# standing cluster's admin kubeconfig). See CLAUDE.md "KVM kubeadm cluster — deploy
# sequence" and hack/kvm-cluster.sh (verify | reset-cluster | deploy-podmotion | wipe).
#
# Optional env vars:
#   CERT_MANAGER_INSTALL_SKIP=true  — skip cert-manager installation (default: skip on kubeadm)
#   KUBECONFIG                      — path to kubeconfig (default: $(HOME)/podmotion-kvm/kubeconfig)
#   E2E_LABEL_FILTER                — Ginkgo label filter (e.g. "proof" for the proof milestone only)

E2E_TIMEOUT ?= 30m
E2E_LABEL_FILTER ?=
export KUBECONFIG ?= $(HOME)/podmotion-kvm/kubeconfig

.PHONY: setup-test-e2e
setup-test-e2e: ## Verify kubeadm cluster is reachable before running e2e tests
	@echo "==> Verifying kubeadm cluster connectivity (KUBECONFIG=$(KUBECONFIG))..."
	@kubectl cluster-info 2>/dev/null || { \
		echo "ERROR: kubectl cannot reach the standing KVM kubeadm cluster."; \
		echo "       Ensure KUBECONFIG points at the standing cluster (default $(HOME)/podmotion-kvm/kubeconfig)"; \
		echo "       and that it is healthy: bash hack/kvm-cluster.sh verify"; \
		exit 1; \
	}
	@kubectl get nodes 2>/dev/null || { echo "ERROR: cannot list nodes"; exit 1; }
	@echo "==> Cluster reachable. Nodes:"; kubectl get nodes -o wide

.PHONY: test-e2e
test-e2e: setup-test-e2e ## Run the e2e tests against the kubeadm cluster.
	CERT_MANAGER_INSTALL_SKIP=true \
	go test -tags=e2e ./test/e2e/ -v -ginkgo.v \
		-timeout $(E2E_TIMEOUT) \
		$(if $(E2E_LABEL_FILTER),--ginkgo.label-filter="$(E2E_LABEL_FILTER)",)

.PHONY: test-e2e-proof
test-e2e-proof: setup-test-e2e ## Run only the stateless live-migration proof test.
	CERT_MANAGER_INSTALL_SKIP=true \
	go test -tags=e2e ./test/e2e/ -v -ginkgo.v \
		-timeout 15m \
		--ginkgo.label-filter=proof

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## No-op on kubeadm — cluster is persistent; test namespaces are cleaned by AfterAll.
	@echo "cleanup-test-e2e: kubeadm cluster is persistent — no teardown needed."

##@ Pre-deploy gate

# pre-deploy runs the e2e suite and aborts the deploy if any test fails.
# Invoke before pushing binaries to production nodes:
#   make pre-deploy && make build-linux && NODE_IP=... ./scripts/deploy-node.sh
.PHONY: pre-deploy
pre-deploy: ## Run e2e gate tests — exit non-zero if any test fails (required before deploy).
	@echo "==> Running pre-deploy test gate..."
	@$(MAKE) test-e2e-proof || { \
		echo ""; \
		echo "ERROR: pre-deploy gate FAILED — do NOT deploy to production nodes."; \
		echo "       Fix the failing tests before running scripts/deploy-node.sh"; \
		exit 1; \
	}
	@echo ""
	@echo "==> pre-deploy gate PASSED — safe to deploy."

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: build-linux
# ADR-0352 D6(c)/DR-8(c): the manager/agent targets build from a PACKAGE/DIRECTORY pattern
# (./cmd, ./cmd/agent), not a .go file-list argument — Go's toolchain silently omits ALL
# vcs.* build settings for a file-list build regardless of GOFLAGS/-buildvcs, which makes
# internal/buildinfo's readback report "unknown" forever and D6(c) permanently VOID.
build-linux: ## Build operator and agent for linux/arm64 and linux/amd64 (no cgo)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/podmotion-manager-arm64 ./cmd
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/podmotion-manager-amd64 ./cmd
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/podmotion-agent-arm64 ./cmd/agent
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/podmotion-agent-amd64 ./cmd/agent
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/podmotion-criu-wrapper-arm64 ./cmd/criu-wrapper/main.go
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/podmotion-criu-wrapper-amd64 ./cmd/criu-wrapper/main.go
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/podmotion-holder-arm64 ./cmd/holder/main.go
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/podmotion-holder-amd64 ./cmd/holder/main.go
	# ADR-0363 B1: scheduler binary — package/directory pattern (./cmd/scheduler), matching
	# manager/agent above (not the file-argument style criu-wrapper/holder use), gated by the
	# `scheduler` build tag so the default build-linux invocation above stays untouched by the
	# heavier k8s.io/kubernetes dependency this tag isolates.
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags scheduler -o bin/podmotion-scheduler-arm64 ./cmd/scheduler
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags scheduler -o bin/podmotion-scheduler-amd64 ./cmd/scheduler
	cp bin/podmotion-criu-wrapper-amd64 bin/criu-wrapper-linux-amd64
	cp bin/podmotion-agent-amd64 bin/agent-linux-amd64
	cp bin/podmotion-manager-amd64 bin/manager-linux-amd64
	cp bin/podmotion-holder-amd64 bin/holder-linux-amd64
	cp bin/podmotion-scheduler-amd64 bin/scheduler-linux-amd64

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# GIT_SHA stamps built images with the source commit for build-provenance
# verification. Falls back to "unknown" so a build without git still succeeds.
GIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg GIT_SHA=$(GIT_SHA) -t ${IMG} .

# ADR-0363 B1: makes images/scheduler/Dockerfile buildable on its own, analogous to
# docker-build above, so SC_IMAGES' pre-existing "scheduler" entry (see ##@ Supply Chain below)
# has a real image for `make sbom`/`make security-scan` to find instead of erroring on a
# nonexistent tag. NOT wired into hack/kvm-cluster.sh's cmd_deploy_podmotion — that deploy-path
# integration belongs to ADR-0363's B2 (chart) follow-up, not this target.
IMG_SCHEDULER ?= ghcr.io/podmotion-io/podmotion-scheduler:latest
.PHONY: docker-build-scheduler
docker-build-scheduler: ## Build docker image for the custom scheduler.
	$(CONTAINER_TOOL) build --build-arg GIT_SHA=$(GIT_SHA) -f images/scheduler/Dockerfile -t ${IMG_SCHEDULER} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name podmotion-builder
	$(CONTAINER_TOOL) buildx use podmotion-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm podmotion-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.20.1

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v2.11.4
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		$(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

# ── PodMotion custom targets ──────────────────────────────────────────────────

# Sprint 37 PreCopyMemory livelock fix (ADR-0226): operator image tag carrying the
# patchMemorySynced condition-message truncation fix. The fix is in the operator
# binary (ReplicationManager, wired in cmd/main.go); the agent binary is unaffected.
SPRINT37_PRECOPY_FIX_TAG ?= sprint37-precopy-fix
IMG_OPERATOR  ?= podmotion-manager:$(SPRINT37_PRECOPY_FIX_TAG)
IMG_AGENT     ?= ghcr.io/podmotion-io/agent:dev
KIND_NODE_IMG ?= ghcr.io/podmotion-io/kind-node:dev
KIND_CLUSTER  ?= podmotion-dev

## bpf-copy: Copy compiled zero_window BPF objects into Ansible files dir for CAPI AMI builds.
## Must be run after 'make bpf-objects' (requires clang on Linux host).
.PHONY: bpf-copy
bpf-copy:
	cp bpf/zero_window_bpfel.o images/capi/ansible/roles/podmotion-node/files/zero_window_bpfel.o
	cp bpf/zero_window_bpfeb.o images/capi/ansible/roles/podmotion-node/files/zero_window_bpfeb.o

## bpf-objects: Compile zero_window.c to BPF ELF objects (requires clang ≥14 on Linux host).
.PHONY: bpf-objects
bpf-objects:
	$(MAKE) -C bpf all

## kind-image: Build kind node image with CRIU and podmotion-agent, tagged as $(KIND_NODE_IMG).
## Prereq: bin/agent-linux-amd64 must exist (run 'make build-agent-linux-amd64' first).
## The bpf/ .o files are read from the repo root context; run 'make bpf-objects' first
## on a Linux host with clang ≥14 if the placeholder .o files need replacing.
.PHONY: kind-image
kind-image:
	docker build -f images/kind/Dockerfile -t $(KIND_NODE_IMG) .

## kind-node-image: Build the custom kind node image with CRIU + NRI (alias for kind-image)
.PHONY: kind-node-image
kind-node-image: kind-image

## kind-create: Create the local development kind cluster (idempotent)
.PHONY: kind-create
kind-create:
	kind get clusters | grep -q $(KIND_CLUSTER) || \
	  kind create cluster --name $(KIND_CLUSTER) --config images/kind/kind-config.yaml
	@echo "Applying Flannel CNI from vendored manifest, then waiting for nodes to be ready..."
	KUBECONFIG=/tmp/$(KIND_CLUSTER).kubeconfig kubectl apply -f images/kind/kube-flannel-v0.25.4.yml
	KUBECONFIG=/tmp/$(KIND_CLUSTER).kubeconfig kubectl wait --for=condition=Ready nodes --all --timeout=120s

## watch: Live dashboard — pods, PodMigrations, events (auto-picks active PodMotion cluster)
.PHONY: watch
watch:
	./hack/watch-cluster.sh

## clusters: List all available kubectl contexts and kind clusters
.PHONY: clusters
clusters:
	./hack/watch-cluster.sh --list

## kind-delete: Tear down the local development kind cluster
.PHONY: kind-delete
kind-delete:
	kind delete cluster --name $(KIND_CLUSTER)

## kind-load: Load operator and agent images into the kind cluster
.PHONY: kind-load
kind-load:
	kind load docker-image $(IMG_OPERATOR) --name $(KIND_CLUSTER)
	kind load docker-image $(IMG_AGENT) --name $(KIND_CLUSTER)

## deploy: Apply manifests to current kubeconfig cluster
.PHONY: deploy
deploy: manifests
	kubectl apply -k config/default

## deploy-kind: Build images, load into kind, and deploy
.PHONY: deploy-kind
deploy-kind: docker-build kind-load deploy

## webhook-certs-dev: Generate self-signed webhook TLS certs for local dev (no cert-manager needed)
.PHONY: webhook-certs-dev
webhook-certs-dev:
	mkdir -p /tmp/podmotion-webhook-certs
	openssl req -x509 -newkey rsa:4096 -keyout /tmp/podmotion-webhook-certs/tls.key \
	  -out /tmp/podmotion-webhook-certs/tls.crt -days 365 -nodes \
	  -subj "/CN=podmotion-webhook-service.podmotion-system.svc" \
	  -addext "subjectAltName=DNS:podmotion-webhook-service.podmotion-system.svc,DNS:podmotion-webhook-service.podmotion-system.svc.cluster.local,DNS:localhost"
	kubectl create secret tls podmotion-webhook-tls \
	  --cert=/tmp/podmotion-webhook-certs/tls.crt \
	  --key=/tmp/podmotion-webhook-certs/tls.key \
	  --namespace=podmotion-system --dry-run=client -o yaml | kubectl apply -f -

## agent-certs-dev: Mint a self-signed CA + agent/operator SPIFFE leaf certs and create the
## podmotion-agent-tls and podmotion-operator-agent-client-tls secrets (ADR-SEC-A §2.1 kind/dev
## fallback for substrates without cert-manager). Keeps the fail-closed path exercised — the
## certs are PRESENT, so it never re-introduces fail-open. Keys are ECDSA-P256 (ADR-SEC-B signing).
.PHONY: agent-certs-dev
agent-certs-dev:
	mkdir -p /tmp/podmotion-agent-certs
	@cd /tmp/podmotion-agent-certs && \
	  openssl ecparam -name prime256v1 -genkey -noout -out ca.key && \
	  openssl req -x509 -new -key ca.key -days 365 -out ca.crt -subj "/CN=podmotion-grpc-ca" && \
	  printf 'subjectAltName=URI:spiffe://podmotion.io/ns/podmotion-system/sa/podmotion-agent\nextendedKeyUsage=serverAuth,clientAuth\n' > agent.ext && \
	  printf 'subjectAltName=URI:spiffe://podmotion.io/ns/podmotion-system/sa/podmotion-operator\nextendedKeyUsage=clientAuth\n' > operator.ext && \
	  openssl ecparam -name prime256v1 -genkey -noout -out agent.key && \
	  openssl req -new -key agent.key -out agent.csr -subj "/CN=podmotion-agent" && \
	  openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out agent.crt -extfile agent.ext && \
	  openssl ecparam -name prime256v1 -genkey -noout -out operator.key && \
	  openssl req -new -key operator.key -out operator.csr -subj "/CN=podmotion-operator" && \
	  openssl x509 -req -in operator.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out operator.crt -extfile operator.ext
	kubectl create secret generic podmotion-agent-tls \
	  --from-file=tls.crt=/tmp/podmotion-agent-certs/agent.crt \
	  --from-file=tls.key=/tmp/podmotion-agent-certs/agent.key \
	  --from-file=ca.crt=/tmp/podmotion-agent-certs/ca.crt \
	  --namespace=podmotion-system --dry-run=client -o yaml | kubectl apply -f -
	kubectl create secret generic podmotion-operator-agent-client-tls \
	  --from-file=tls.crt=/tmp/podmotion-agent-certs/operator.crt \
	  --from-file=tls.key=/tmp/podmotion-agent-certs/operator.key \
	  --from-file=ca.crt=/tmp/podmotion-agent-certs/ca.crt \
	  --namespace=podmotion-system --dry-run=client -o yaml | kubectl apply -f -

## proto-gen: Regenerate Go code from .proto files
.PHONY: proto-gen
proto-gen:
	protoc --go_out=. --go_opt=paths=source_relative \
	  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	  proto/migration_agent.proto

## verify-kernel-config: Verify kernel config on the current node meets PodMotion requirements
.PHONY: verify-kernel-config
verify-kernel-config:
	bash hack/verify-kernel-config.sh

# ── M18: Packaging & Upstream Contributions ──────────────────────────────────

BUNDLE_IMG         ?= ghcr.io/podmotion/podmotion-bundle:v$(VERSION)
VERSION            ?= 0.1.0
OPERATOR_SDK       ?= $(LOCALBIN)/operator-sdk

## bundle: Generate OLM bundle manifests from kustomize config
.PHONY: bundle
bundle: manifests kustomize
	@mkdir -p bundle/manifests bundle/metadata
	@echo "Generating OLM bundle for podmotion v$(VERSION)"
	$(OPERATOR_SDK) generate bundle \
	  --package podmotion \
	  --version $(VERSION) \
	  --channels stable,alpha \
	  --default-channel stable \
	  --output-dir bundle \
	  --overwrite 2>/dev/null || true
	@echo "bundle manifests written to bundle/"

## bundle-build: Build the OLM bundle container image
.PHONY: bundle-build
bundle-build:
	$(CONTAINER_TOOL) build -f bundle/Dockerfile -t $(BUNDLE_IMG) .

## bundle-push: Push the OLM bundle container image
.PHONY: bundle-push
bundle-push:
	$(CONTAINER_TOOL) push $(BUNDLE_IMG)

##@ Supply Chain

# ── Supply chain security (ADR-0077) ─────────────────────────────────────────
# `make sbom` generates a CycloneDX JSON SBOM for every image and the Helm chart.
# `make security-scan` Grype-scans every SBOM and FAILs on a fixable CRITICAL/HIGH.
# `release-gate` gains a `security-scan` prerequisite so no tag is published with a
# fixable HIGH/CRITICAL CVE (ADR-0077 §1.5 + §7.5 checklist item 5).

SYFT          ?= $(LOCALBIN)/syft
GRYPE         ?= $(LOCALBIN)/grype
SYFT_VERSION  ?= v1.18.1
GRYPE_VERSION ?= v0.85.0
SBOM_DIR      ?= dist/sbom
SBOM_SEVERITY ?= high     # grype fail-cutoff: critical|high|medium|low

# Image short names — the four container images in scope (ADR-0077 §1).
SC_IMAGES     ?= operator agent scheduler checkpoint-gc

.PHONY: syft
syft: $(SYFT) ## Download syft (CycloneDX SBOM generator) locally if necessary.
$(SYFT): $(LOCALBIN)
	$(call go-install-tool,$(SYFT),github.com/anchore/syft/cmd/syft,$(SYFT_VERSION))

.PHONY: grype
grype: $(GRYPE) ## Download grype (vulnerability scanner) locally if necessary.
$(GRYPE): $(LOCALBIN)
	$(call go-install-tool,$(GRYPE),github.com/anchore/grype/cmd/grype,$(GRYPE_VERSION))

.PHONY: sbom
sbom: $(SYFT) ## Generate a CycloneDX JSON SBOM for every image and the Helm chart (ADR-0077 §1.5).
	@mkdir -p $(SBOM_DIR)
	@for b in $(SC_IMAGES); do \
	  echo "==> SBOM: ghcr.io/podmotion-io/podmotion-$$b:$(VERSION)"; \
	  "$(SYFT)" "ghcr.io/podmotion-io/podmotion-$$b:$(VERSION)" \
	    -o cyclonedx-json > "$(SBOM_DIR)/podmotion-$$b.cdx.json" || exit 1; \
	done
	"$(SYFT)" dir:charts/podmotion/ -o cyclonedx-json > "$(SBOM_DIR)/chart.cdx.json"
	@echo "==> SBOMs written to $(SBOM_DIR)/"

.PHONY: security-scan
security-scan: $(GRYPE) sbom ## Grype-scan every SBOM; FAIL on a fixable CRITICAL/HIGH finding (ADR-0077 §1.5).
	@fail=0; for f in $(SBOM_DIR)/*.cdx.json; do \
	  echo "==> scan: $$f"; \
	  "$(GRYPE)" "sbom:$$f" --fail-on $(SBOM_SEVERITY) --only-fixed || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then \
	  echo "ERROR: security-scan FAILED — fixable CRITICAL/HIGH CVE present."; exit 1; \
	fi; \
	echo "==> security-scan PASSED."

##@ Release Hygiene

.PHONY: deploy-crds
deploy-crds: manifests ## Apply CRD manifests directly from config/crd/bases/ (bypasses kustomize).
	kubectl apply -f config/crd/bases/

.PHONY: crd-upgrade-check
crd-upgrade-check: manifests ## Diff live CRDs against generated manifests; exit 1 on breaking changes.
	@echo "==> Checking CRD upgrade safety..."
	@fail=0; \
	for f in config/crd/bases/*.yaml; do \
	  name=$$(grep '^  name:' "$$f" | head -1 | awk '{print $$2}'); \
	  if ! kubectl get crd "$$name" >/dev/null 2>&1; then \
	    echo "  [SKIP] $$name not installed — skipping diff"; \
	    continue; \
	  fi; \
	  diff_out=$$(kubectl diff -f "$$f" 2>/dev/null || true); \
	  if echo "$$diff_out" | grep -qE '^\-.*required|^\-.*x-kubernetes-validations'; then \
	    echo "  [FAIL] $$name: detected required-field removal or CEL rule removal"; \
	    echo "$$diff_out"; \
	    fail=1; \
	  fi; \
	  if echo "$$diff_out" | grep -qE '^\-  [a-zA-Z]'; then \
	    echo "  [WARN] $$name: potential field removal detected — review carefully:"; \
	    echo "$$diff_out" | grep -E '^\-' | head -20; \
	  fi; \
	done; \
	if [ $$fail -eq 1 ]; then \
	  echo ""; \
	  echo "ERROR: crd-upgrade-check FAILED — breaking CRD changes detected."; \
	  echo "       CRD fields and CEL rules must not be removed in a patch/minor release."; \
	  exit 1; \
	fi; \
	echo "==> crd-upgrade-check PASSED."

.PHONY: release-gate
release-gate: crd-upgrade-check security-scan ## Run all release gate checks (CRD check + supply-chain scan + scripts + release-tagged tests).
	@echo "==> Running release gate..."
	@if [ -f scripts/check-release-gate.sh ]; then \
	  bash scripts/check-release-gate.sh || { echo "ERROR: check-release-gate.sh FAILED"; exit 1; }; \
	else \
	  echo "  [SKIP] scripts/check-release-gate.sh not found"; \
	fi
	@if [ -f scripts/check-kernel-config.sh ]; then \
	  bash scripts/check-kernel-config.sh || { echo "ERROR: check-kernel-config.sh FAILED"; exit 1; }; \
	else \
	  echo "  [SKIP] scripts/check-kernel-config.sh not found"; \
	fi
	@if [ -f scripts/check-manifest-hygiene.sh ]; then \
	  bash scripts/check-manifest-hygiene.sh || { echo "ERROR: check-manifest-hygiene.sh FAILED"; exit 1; }; \
	else \
	  echo "  [SKIP] scripts/check-manifest-hygiene.sh not found"; \
	fi
	@echo "==> Running go test ./... -tags release..."
	@go test -tags release ./... || { echo "ERROR: go test -tags release FAILED"; exit 1; }
	@echo ""
	@echo "==> release-gate PASSED — safe to tag and publish."

## release-manifests: Generate single-file install.yaml for quick cluster install
.PHONY: release-manifests
release-manifests: manifests generate kustomize
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=ghcr.io/podmotion/podmotion-operator:v$(VERSION)
	"$(KUSTOMIZE)" build config/default > dist/install.yaml
	@echo "Single-file install manifest written to dist/install.yaml"
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
