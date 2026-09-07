/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0423_v12_envtest_test.go implements ADR-0423 V12 Row 1 against the real envtest apiserver
// (suite_test.go's k8sClient), which installs the actual generated CRD schema — the fake client
// performs no schema validation or pruning at all, so it cannot exercise, let alone falsify, the
// CRD-not-yet-reapplied class of defect patchRollbackProgress's read-back (Fix 3) and D4(c)'s
// fall-through (Fix 1) exist to survive (round-7 KVM finding).

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

var _ = Describe("ADR-0423 V12 Row 1 — patchRollbackProgress against the real envtest CRD schema", func() {
	It("durably stamps RollbackStartTime and the stamp survives a fresh Get through the real apiserver", func() {
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{Name: "adr0423-v12-row1", Namespace: "default"},
			Spec: pmv1.PodMigrationSpec{
				PodName:      "v12-src-pod",
				PodNamespace: "default",
			},
		}
		Expect(k8sClient.Create(ctx, pm)).To(Succeed())
		defer func() { _ = k8sClient.Delete(ctx, pm) }()

		r := &PodMigrationReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), APIReader: k8sClient}

		now := metav1.Now()
		stamped, err := r.patchRollbackProgress(ctx, pm, &now, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(stamped).To(BeTrue(), "patchRollbackProgress must confirm durability via its read-back against the real CRD schema")

		fresh := &pmv1.PodMigration{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: pm.Name, Namespace: pm.Namespace}, fresh)).To(Succeed())
		Expect(fresh.Status.RollbackStartTime).NotTo(BeNil(), "RollbackStartTime must have durably persisted through the real generated CRD — a stale/unapplied schema would silently prune it")
	})
})
