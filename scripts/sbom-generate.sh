#!/usr/bin/env bash
# sbom-generate.sh — Generate a CycloneDX JSON SBOM for PodMotion.
#
# Preferred tool: syft (https://github.com/anchore/syft)
# Fallback tool:  cyclonedx-gomod (https://github.com/CycloneDX/cyclonedx-gomod)
#
# Output: release/sbom.cyclonedx.json
#
# Usage:
#   bash scripts/sbom-generate.sh
#
# CI usage (GitHub Actions):
#   - uses: anchore/sbom-action@v0
#     with:
#       format: cyclonedx-json
#       output-file: release/sbom.cyclonedx.json

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/release"
OUTPUT_FILE="${OUTPUT_DIR}/sbom.cyclonedx.json"

mkdir -p "${OUTPUT_DIR}"

echo "==> Generating CycloneDX JSON SBOM for PodMotion..."
echo "    Output: ${OUTPUT_FILE}"

if command -v syft &>/dev/null; then
  echo "==> Using syft $(syft version 2>/dev/null | head -1 || true)"
  syft dir:"${REPO_ROOT}" \
    --output cyclonedx-json="${OUTPUT_FILE}" \
    --select-catalogers "+go-module-binary-cataloger"
  echo "==> SBOM written to ${OUTPUT_FILE}"

elif command -v cyclonedx-gomod &>/dev/null; then
  echo "==> Using cyclonedx-gomod"
  cd "${REPO_ROOT}"
  cyclonedx-gomod app \
    -json \
    -output "${OUTPUT_FILE}" \
    -main cmd/operator/main.go \
    .
  echo "==> SBOM written to ${OUTPUT_FILE}"

else
  echo ""
  echo "WARNING: Neither syft nor cyclonedx-gomod is installed."
  echo "         SBOM generation skipped — install one of the following:"
  echo ""
  echo "  syft (recommended):"
  echo "    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
  echo "    # or: brew install syft"
  echo ""
  echo "  cyclonedx-gomod:"
  echo "    go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest"
  echo ""
  echo "  In GitHub Actions, use the anchore/sbom-action step instead:"
  echo "    - uses: anchore/sbom-action@v0"
  echo "      with:"
  echo "        format: cyclonedx-json"
  echo "        output-file: release/sbom.cyclonedx.json"
  echo ""
  exit 0
fi
