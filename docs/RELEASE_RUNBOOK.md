# PodMotion Release Runbook

This runbook covers cutting a PodMotion release from a clean main branch to published artifacts.

---

## Pre-Release Checklist

Run the release gate before tagging:

```bash
VERSION=v0.2.0 make release-gate
```

`make release-gate` runs in order:

1. `scripts/check-release-gate.sh` — asserts green-streak conditions from the CI matrix
2. `scripts/check-kernel-config.sh` — validates kernel config requirements
3. `make crd-upgrade-check` — diffs live CRDs against generated manifests; fails on breaking changes
4. `go test ./... -tags release` — runs all tests including release-only build-tag tests

All four steps must pass before tagging. Do not proceed if any step exits non-zero.

Additional manual checks:

- [ ] `CHANGELOG.md` entry written with migration notes for any CRD schema changes
- [ ] Helm chart `version` and `appVersion` bumped in `charts/podmotion/Chart.yaml`
- [ ] `dist/install.yaml` regenerated: `make release-manifests VERSION=<tag>`
- [ ] SBOM generated: `bash scripts/sbom-generate.sh` — output at `release/sbom.cyclonedx.json`
- [ ] All E2E tests passing on the PoC cluster: `make test-e2e`

---

## CRD Upgrade Warning for Helm Users

PodMotion CRDs are **not** managed by Helm by default (they live in `crds/` but Helm does not
upgrade CRDs on `helm upgrade`). Operators must apply CRD updates manually before upgrading the
chart:

```bash
# Option A — via make (recommended)
make deploy-crds

# Option B — direct kubectl
kubectl apply -f config/crd/bases/

# Option C — from the release tarball
kubectl apply -f https://github.com/podmotion-io/podmotion/releases/download/<tag>/crds.yaml
```

Failure to apply CRDs before upgrading the chart will cause the controller to crash-loop if new
API fields are referenced.

`make crd-upgrade-check` validates that the upgrade is safe (no required-field additions, no field
removals, no CEL rule removals). Run it against the cluster you intend to upgrade before applying.

---

## Tagging and Publishing

```bash
git tag -s v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

The GitHub Actions release workflow (`.github/workflows/release.yml`) then:

1. Builds and pushes the four images (`operator`, `agent`, `scheduler`, `kind-node`)
2. Signs each image with cosign keyless signing via SLSA GitHub Generator
3. Generates and attaches the `.intoto.jsonl` SLSA L2 provenance attestation
4. Attaches `dist/install.yaml`, `release/sbom.cyclonedx.json`, and `crds.yaml` to the release

---

## Cosign Image Verification

Operators can verify a signed release image before deploying:

```bash
cosign verify \
  --certificate-identity-regexp \
    'https://github.com/podmotion-io/podmotion/.github/workflows/release.yml.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/podmotion-io/operator:v0.2.0
```

To verify SLSA L2 provenance:

```bash
slsa-verifier verify-image \
  --source-uri github.com/podmotion-io/podmotion \
  --source-tag v0.2.0 \
  ghcr.io/podmotion-io/operator:v0.2.0
```

All four images (`operator`, `agent`, `scheduler`, `kind-node`) are signed and have provenance
attestations attached. The same `cosign verify` command applies to each — substitute the image
name accordingly.

---

## Post-Release

- [ ] Announce on the podmotion-io community channel
- [ ] Update `docs/MILESTONES.md` to mark the milestone complete
- [ ] Open the next milestone planning issue
