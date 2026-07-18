//go:build e2e
// +build e2e

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/test/utils"
)

const (
	sprint31Namespace    = "pm-e2e-sprint31"
	sprint31PodName      = "e2e-sprint31-redis"
	sprint31WorkerNode   = "podmotion-sprint31-worker"
	sprint31ControlPlane = "podmotion-sprint31-control-plane"
	sprint31RedisKey     = "sprint31_key"
	sprint31RedisVal     = "sprint31_northstar_amd64"
)

var _ = Describe("Cold Migration [cold-migration-amd64]", Ordered, Label("cold-migration-amd64"), func() {
	var (
		k8sClient   client.Client
		sourcePodName string
	)

	BeforeAll(func() {
		var err error
		k8sClient, err = utils.NewPMClient()
		Expect(err).NotTo(HaveOccurred(), "creating k8s client")

		By("creating sprint31 e2e namespace")
		cmd := exec.Command("kubectl", "create", "namespace", sprint31Namespace, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("deploying Redis pod to worker node " + sprint31WorkerNode)
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      sprint31PodName,
				Namespace: sprint31Namespace,
				Labels: map[string]string{
					"app":    sprint31PodName,
					"sprint": "31",
				},
			},
			Spec: corev1.PodSpec{
				NodeName:      sprint31WorkerNode,
				RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{
					{
						Name:  "redis",
						Image: "redis:7-alpine",
						Ports: []corev1.ContainerPort{
							{ContainerPort: 6379, Protocol: corev1.ProtocolTCP},
						},
					},
				},
			},
		}
		ctx := context.Background()
		Expect(k8sClient.Create(ctx, pod)).To(Succeed(), "creating sprint31 Redis pod")
		sourcePodName = sprint31PodName

		By("waiting for Redis pod to be Ready")
		Expect(utils.WaitForPodReady(ctx, k8sClient, sprint31PodName, sprint31Namespace,
			2*time.Minute, 3*time.Second)).To(Succeed())

		By("seeding " + sprint31RedisKey + "=" + sprint31RedisVal)
		Eventually(func() error {
			cmd := exec.Command("kubectl", "exec", "-n", sprint31Namespace,
				sprint31PodName, "--", "redis-cli", "set", sprint31RedisKey, sprint31RedisVal)
			_, err := utils.Run(cmd)
			return err
		}, 30*time.Second, 3*time.Second).Should(Succeed(), "SET sprint31_key in Redis")
	})

	AfterAll(func() {
		By("cleaning up sprint31 e2e namespace")
		cmd := exec.Command("kubectl", "delete", "namespace", sprint31Namespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	It("completes cold CRIU migration cross-node on amd64 kind", func(ctx SpecContext) {
		By("creating PodMigration targeting " + sprint31ControlPlane + " with tcpPreservationMode=None")
		pm := &pmv1.PodMigration{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "pm-sprint31-amd64-",
				Namespace:    sprint31Namespace,
			},
			Spec: pmv1.PodMigrationSpec{
				PodName:                  sprint31PodName,
				PodNamespace:             sprint31Namespace,
				Mode:                     pmv1.MigrationModeCold,
				TargetNodeName:           sprint31ControlPlane,
				TCPPreservationMode:      pmv1.TCPPreservationModeNone,
				RollbackOnFailure:        true,
				CompletionTimeoutSeconds: 300,
			},
		}
		Expect(k8sClient.Create(ctx, pm)).To(Succeed(), "creating sprint31 PodMigration CR")
		defer func() { _ = k8sClient.Delete(ctx, pm) }()

		By("waiting for PodMigration to reach Complete phase (5 min timeout)")
		Eventually(func() pmv1.MigrationPhase {
			_ = k8sClient.Get(ctx, types.NamespacedName{
				Namespace: pm.Namespace,
				Name:      pm.Name,
			}, pm)
			return pm.Status.Phase
		}, 5*time.Minute, 3*time.Second).Should(Equal(pmv1.MigrationPhaseComplete),
			"migration should reach Complete, not Failed")

		By("verifying phase is Complete (not Failed)")
		Expect(pm.Status.Phase).To(Equal(pmv1.MigrationPhaseComplete),
			"PodMigration phase must be Complete")

		By("verifying criuRestoreConfirmed=true on PodMigration CR")
		Expect(pm.Status.CRIURestoreConfirmed).NotTo(BeNil(),
			"CRIURestoreConfirmed should be set")
		Expect(*pm.Status.CRIURestoreConfirmed).To(BeTrue(),
			"criuRestoreConfirmed must be true (NRI plugin confirmed restore)")

		By("verifying replacement pod is on " + sprint31ControlPlane)
		Expect(pm.Status.DestinationNodeName).To(Equal(sprint31ControlPlane),
			"replacement pod must land on podmotion-sprint31-control-plane")

		By("verifying source pod is deleted (ADR-0012)")
		Expect(waitForSourcePodGone(sprint31Namespace, sourcePodName, 30*time.Second)).To(Succeed(),
			"source pod must be deleted after successful migration (ADR-0012)")

		By("verifying redis-cli GET " + sprint31RedisKey + " returns " + sprint31RedisVal + " from replacement pod")
		replacementPod := pm.Status.ReplacementPodName
		Expect(replacementPod).NotTo(BeEmpty(), "ReplacementPodName must be set on PodMigration status")

		Eventually(func() (string, error) {
			cmd := exec.Command("kubectl", "exec", "-n", sprint31Namespace,
				replacementPod, "--", "redis-cli", "get", sprint31RedisKey)
			out, err := utils.Run(cmd)
			return strings.TrimSpace(out), err
		}, 30*time.Second, 3*time.Second).Should(Equal(sprint31RedisVal),
			fmt.Sprintf("redis-cli GET %s must return %q from replacement pod after CRIU restore",
				sprint31RedisKey, sprint31RedisVal))
	}, SpecTimeout(6*time.Minute))
})
