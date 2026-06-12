//go:build e2e
// +build e2e

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

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/podmotion-io/podmotion/test/utils"
)

var (
	// managerImage is unused when targeting a pre-deployed kubeadm cluster.
	managerImage = "example.com/podmotion:v0.0.1"
	// shouldCleanupCertManager tracks whether CertManager was installed by this suite.
	shouldCleanupCertManager = false
)

// TestE2E runs the e2e test suite against the kubeadm cluster.
//
// Cluster selection (in priority order):
//   1. KUBECONFIG env var — explicit kubeconfig path
//   2. ~/.kube/config     — default kubeconfig
//
// Kind cluster creation is intentionally skipped; tests run against a real kubeadm
// cluster (pm-control: 192.168.252.7, pm-worker: 192.168.252.8).
//
// Optional env vars:
//   CERT_MANAGER_INSTALL_SKIP=true  — skip cert-manager installation check
//   KUBECTL_KUBERC=true             — re-enable kubectl kuberc
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting podmotion e2e test suite (kubeadm cluster)\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	// Skip image build and Kind loading — the kubeadm cluster already has
	// the operator and agent running as systemd services on pm-control/pm-worker.
	_, _ = fmt.Fprintf(GinkgoWriter,
		"BeforeSuite: targeting kubeadm cluster (skipping docker-build and kind image load)\n")

	configureKubectlKubeRC()
	setupCertManager()
	resetNodeMigrationCapacity()
})

// resetNodeMigrationCapacity resets stale activeDestinationMigrations /
// activeSourceMigrations counts on all NMC objects before the test suite runs.
// On the shared kubeadm cluster previous test runs may leave stale counters
// when migrations are cleaned up without the operator decrementing the NMC.
func resetNodeMigrationCapacity() {
	By("resetting stale NodeMigrationCapacity active migration counts")
	patch := `{"status":{"activeDestinationMigrations":0,"activeSourceMigrations":0}}`
	cmd := exec.Command("kubectl", "get", "nodemigrationcapacities",
		"-o", "jsonpath={.items[*].metadata.name}")
	out, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "warning: could not list NMCs: %v\n", err)
		return
	}
	for _, name := range strings.Fields(out) {
		patchCmd := exec.Command("kubectl", "patch", "nodemigrationcapacity", name,
			"--subresource=status",
			"--type=merge",
			fmt.Sprintf("--patch=%s", patch))
		if _, patchErr := utils.Run(patchCmd); patchErr != nil {
			_, _ = fmt.Fprintf(GinkgoWriter,
				"warning: could not reset NMC %s: %v\n", name, patchErr)
		} else {
			_, _ = fmt.Fprintf(GinkgoWriter, "reset NMC %s active counts to 0\n", name)
		}
	}
}

var _ = AfterSuite(func() {
	teardownCertManager()
})

// Disable kubectl kuberc by default for test isolation.
// This prevents local kubectl configurations from affecting test behavior.
// To enable kuberc, set: KUBECTL_KUBERC=true
func configureKubectlKubeRC() {
	if os.Getenv("KUBECTL_KUBERC") != "true" {
		By("disabling kubectl kuberc for test isolation")
		err := os.Setenv("KUBECTL_KUBERC", "false")
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to disable kubectl kuberc")
		_, _ = fmt.Fprintf(GinkgoWriter,
			"kubectl kuberc disabled for consistent test behavior (override with KUBECTL_KUBERC=true)\n")
	} else {
		_, _ = fmt.Fprintf(GinkgoWriter, "kubectl kuberc enabled (KUBECTL_KUBERC=true)\n")
	}
}

// setupCertManager installs CertManager if needed for webhook tests.
// Skips installation if CERT_MANAGER_INSTALL_SKIP=true or if already present.
func setupCertManager() {
	if os.Getenv("CERT_MANAGER_INSTALL_SKIP") == "true" {
		_, _ = fmt.Fprintf(GinkgoWriter, "Skipping CertManager installation (CERT_MANAGER_INSTALL_SKIP=true)\n")
		return
	}

	By("checking if CertManager is already installed")
	if utils.IsCertManagerCRDsInstalled() {
		_, _ = fmt.Fprintf(GinkgoWriter, "CertManager is already installed. Skipping installation.\n")
		return
	}

	// Mark for cleanup before installation to handle interruptions and partial installs.
	shouldCleanupCertManager = true

	By("installing CertManager")
	Expect(utils.InstallCertManager()).To(Succeed(), "Failed to install CertManager")
}

// teardownCertManager uninstalls CertManager if it was installed by setupCertManager.
// This ensures we only remove what we installed.
func teardownCertManager() {
	if !shouldCleanupCertManager {
		_, _ = fmt.Fprintf(GinkgoWriter, "Skipping CertManager cleanup (not installed by this suite)\n")
		return
	}

	By("uninstalling CertManager")
	utils.UninstallCertManager()
}
