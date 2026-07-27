/*
Copyright 2026 PodMotion Authors.

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

package server

// reattach_label_resolve_test.go — pinned regression for the postgres restore frontier: the
// re-attach (Tier0 RWX) volume host target must be resolved by the migration-name LABEL the
// controller stamps on the replacement pod, NOT by pm.Status.ReplacementPodName (which reads back
// empty at restore time and produced the broken 1:1 container-path --ext-mount-map that aborted
// CRIU restore with open_tree ENOENT).
//
// The test reproduces the exact observed state — Status.ReplacementPodName EMPTY, but a labelled
// replacement pod present on the destination — and asserts resolveReattachMounts resolves the real
// kubelet host path via the label, so buildCRIURestoreArgs emits <containerPath>:<kubeletHostDir>
// instead of the 1:1 container path. Before the label fix this returned an empty HostTarget (then
// the 1:1 fallback); after it, the host target is present.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/criu"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeAgentServerWithCoreObjects(t *testing.T, objs ...client.Object) *AgentServer {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme (pmv1): %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme (corev1): %v", err)
	}
	if err := storagev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme (storagev1): %v", err)
	}
	builder := fake.NewClientBuilder().WithScheme(scheme)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	return New("test-node", &criu.StubCheckpointer{}, builder.Build())
}

// TestResolveReattachMounts_ResolvesHostTargetByLabelWhenStatusEmpty is the core regression: with
// Status.ReplacementPodName empty but a labelled replacement pod present, the host target resolves
// via the label so the emitted ext-mount-map uses the kubelet host path (not the broken 1:1 map).
func TestResolveReattachMounts_ResolvesHostTargetByLabelWhenStatusEmpty(t *testing.T) {
	const migName = "postgres-live-migration"
	const replUID = "b1bffab8-74e2-4a8a-ad72-f6d5d5436fcb"
	const pvName = "pvc-bbf8a46b"
	const containerPath = "/var/lib/postgresql/data"
	wantHost := "/var/lib/kubelet/pods/" + replUID + "/volumes/kubernetes.io~nfs/" + pvName

	// Stub the on-host glob: return the kubelet dir ONLY for the labelled replacement pod's UID.
	orig := kubeletVolumeGlobFn
	t.Cleanup(func() { kubeletVolumeGlobFn = orig })
	kubeletVolumeGlobFn = func(_ context.Context, uid, pv string) string {
		if uid == replUID && pv == pvName {
			return wantHost
		}
		return ""
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "postgres-src", PodNamespace: "default"},
		// Status.ReplacementPodName deliberately EMPTY — the observed restore-time race.
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "postgres-pgdata", Namespace: "default"},
		Spec: corev1.PersistentVolumeClaimSpec{
			VolumeName:  pvName,
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}, // Tier0 re-attach
		},
	}
	// The replacement pod carries the authoritative migration-name label (stamped by the
	// controller) even though Status.ReplacementPodName was never persisted.
	replPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "postgres-src-m-cbde3794",
			Namespace: "default",
			UID:       replUID,
			Labels:    map[string]string{replacementPodLabelKey: migName},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name: "pgdata",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "postgres-pgdata"},
				},
			}},
			Containers: []corev1.Container{{
				Name:         "postgres",
				VolumeMounts: []corev1.VolumeMount{{Name: "pgdata", MountPath: containerPath}},
			}},
		},
	}
	s := newFakeAgentServerWithCoreObjects(t, pm, pvc, replPod)

	mounts, err := s.resolveReattachMounts(context.Background(), migName)
	if err != nil {
		t.Fatalf("resolveReattachMounts returned error with a resolved host target: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected exactly 1 re-attach mount, got %d: %+v", len(mounts), mounts)
	}
	if mounts[0].ContainerPath != containerPath {
		t.Errorf("container path: got %q, want %q", mounts[0].ContainerPath, containerPath)
	}
	if mounts[0].HostTarget != wantHost {
		t.Fatalf("host target NOT resolved by label: got %q, want %q (this is the Sprint-44 root cause — empty host target → broken 1:1 map)", mounts[0].HostTarget, wantHost)
	}

	// End-to-end: the resolved host target is applied by rewriting the checkpoint image's recorded
	// source to it (patchCheckpointImages) — CRIU binds mi->source directly for an AUTODETECTED_MOUNT
	// and bypasses --ext-mount-map. So buildCRIURestoreArgs must NOT emit an inert path-form map, and
	// the resolved host target must be projected into the patch's host-target map (its real consumer).
	args, err := buildCRIURestoreArgs(
		"/ckpt", "/rootfs", "/data", "/termlog", "/secrets", "/restore.log",
		"", "/var/run/netns/cni-x", "", false, mounts, nil)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs returned error with a resolved host target: %v", err)
	}
	if joined := strings.Join(args, " "); strings.Contains(joined, "--ext-mount-map "+containerPath+":") {
		t.Errorf("must NOT emit an inert path-form re-attach ext-mount-map for %s (CRIU bypasses it for autodetected externals); got: %s", containerPath, joined)
	}
	if ht := reattachHostTargets(mounts); ht[containerPath] != wantHost {
		t.Errorf("resolved host target must be projected into the patch host-target map: got %q, want %q", ht[containerPath], wantHost)
	}
}

// TestResolveReattachMounts_BareNFSVolumeNoPVC is the sprint53-kind EC2/ADR-0193-P-0193-1 regression:
// a pod spec whose volume is a BARE pod-spec `nfs:` source with NO PersistentVolumeClaim wrapper —
// the exact shape used on a cluster with no StorageClass/CSI, where the postgres PGDATA mount was pointed at
// a raw NFS export instead of a PVC. Before the fix, resolveReattachMountsImpl was keyed exclusively
// on v.PersistentVolumeClaim, so this pod's PGDATA volume never entered pvcVolToClaim, the function
// returned an EMPTY reattach set, and patch_checkpoint_script.go's ADR-0194 B-2 drop pass discarded
// the mount as an unresolved external — orphaning its open REG fds (the live postgres WAL segment)
// into the ADR-0193 P-0193-1 DECLINE hard-stop at restore time, even though
// internal/agent/storage.classifier's StorageReadyForFreeze precondition had already reported the
// same volume as Tier0/RWX-ready. This test fails before the fix (empty mounts) and passes after
// (the NFS mount resolves with Tier0RWX and its real kubelet host target).
func TestResolveReattachMounts_BareNFSVolumeNoPVC(t *testing.T) {
	const migName = "postgres-live-migration"
	const replUID = "c2a1d9e0-1111-4a8a-ad72-f6d5d5436abc"
	const volName = "pgdata"
	const containerPath = "/var/lib/postgresql/data"
	wantHost := "/var/lib/kubelet/pods/" + replUID + "/volumes/kubernetes.io~nfs/" + volName

	orig := kubeletVolumeGlobFn
	t.Cleanup(func() { kubeletVolumeGlobFn = orig })
	kubeletVolumeGlobFn = func(_ context.Context, uid, pv string) string {
		if uid == replUID && pv == volName {
			return wantHost
		}
		return ""
	}

	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "postgres-src", PodNamespace: "default"},
	}
	// No PVC object at all — the pod spec's volume is a bare `nfs:` source.
	replPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "postgres-src-m-bare-nfs",
			Namespace: "default",
			UID:       types.UID(replUID),
			Labels:    map[string]string{replacementPodLabelKey: migName},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name: volName,
				VolumeSource: corev1.VolumeSource{
					NFS: &corev1.NFSVolumeSource{Server: "10.60.1.225", Path: "/export/pgdata"},
				},
			}},
			Containers: []corev1.Container{{
				Name:         "postgres",
				VolumeMounts: []corev1.VolumeMount{{Name: volName, MountPath: containerPath}},
			}},
		},
	}
	s := newFakeAgentServerWithCoreObjects(t, pm, replPod)

	mounts, err := s.resolveReattachMounts(context.Background(), migName)
	if err != nil {
		t.Fatalf("resolveReattachMounts returned error for a bare NFS volume with a resolved host target: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected exactly 1 re-attach mount for the bare NFS volume, got %d: %+v", len(mounts), mounts)
	}
	if mounts[0].ContainerPath != containerPath {
		t.Errorf("container path: got %q, want %q", mounts[0].ContainerPath, containerPath)
	}
	if mounts[0].HostTarget != wantHost {
		t.Fatalf("bare-NFS host target NOT resolved: got %q, want %q (P-0193-1 regression: an empty reattach set here means the mount gets B-2 dropped and its fds DECLINE at restore)", mounts[0].HostTarget, wantHost)
	}
	if mounts[0].Tier != reattachTierTier0RWX {
		t.Errorf("bare NFS volume must classify as Tier0 RWX re-attach: got tier %d", mounts[0].Tier)
	}

	// End-to-end: the resolved host target must reach the patch-script host-target map, the actual
	// consumer that keeps patch_checkpoint_script.go from B-2-dropping this mount.
	if ht := reattachHostTargets(mounts); ht[containerPath] != wantHost {
		t.Errorf("resolved bare-NFS host target must be projected into the patch host-target map: got %q, want %q", ht[containerPath], wantHost)
	}
}

// reattachTestFixture builds a (pm, pvc, replPod) triad wired for the re-attach resolver: an empty
// Status.ReplacementPodName, a labelled replacement pod, and a single PVC-backed volume mount.
func reattachTestFixture(migName, replUID, pvName, containerPath string) (*pmv1.PodMigration, *corev1.PersistentVolumeClaim, *corev1.Pod) {
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: migName, Namespace: "default"},
		Spec:       pmv1.PodMigrationSpec{PodName: "postgres-src", PodNamespace: "default"},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "postgres-pgdata", Namespace: "default"},
		Spec: corev1.PersistentVolumeClaimSpec{
			VolumeName:  pvName,
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}, // Tier0 re-attach
		},
	}
	replPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "postgres-src-m-cbde3794",
			Namespace: "default",
			UID:       types.UID(replUID),
			Labels:    map[string]string{replacementPodLabelKey: migName},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name: "pgdata",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "postgres-pgdata"},
				},
			}},
			Containers: []corev1.Container{{
				Name:         "postgres",
				VolumeMounts: []corev1.VolumeMount{{Name: "pgdata", MountPath: containerPath}},
			}},
		},
	}
	return pm, pvc, replPod
}

// TestResolveReattachMounts_WaitsThenResolvesWhenVolumeNotYetPublished proves the mount-vs-restore
// ordering fix: the single-shot resolver returns the retryable *ReattachVolumeNotYetPublishedError
// (NOT a HostTarget=="" mount) while the kubelet has not yet published the volume, and the bounded
// waiter converges to the resolved kubelet mount leaf once the publish lands. Before the fix the
// first empty probe fell straight to the fail-closed guard, so "resolves after wait" fails before
// and passes after.
func TestResolveReattachMounts_WaitsThenResolvesWhenVolumeNotYetPublished(t *testing.T) {
	const migName = "postgres-live-migration"
	const replUID = "b1bffab8-74e2-4a8a-ad72-f6d5d5436fcb"
	const pvName = "pvc-bbf8a46b"
	const containerPath = "/var/lib/postgresql/data"
	wantLeaf := "/var/lib/kubelet/pods/" + replUID + "/volumes/kubernetes.io~csi/" + pvName + "/mount"

	// Simulate the publish window: return "" for the first 2 probes, then the real kubelet leaf.
	var mu sync.Mutex
	calls := 0
	orig := kubeletVolumeGlobFn
	t.Cleanup(func() { kubeletVolumeGlobFn = orig })
	kubeletVolumeGlobFn = func(_ context.Context, uid, pv string) string {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls <= 2 {
			return ""
		}
		if uid == replUID && pv == pvName {
			return wantLeaf
		}
		return ""
	}

	pm, pvc, replPod := reattachTestFixture(migName, replUID, pvName, containerPath)
	s := newFakeAgentServerWithCoreObjects(t, pm, pvc, replPod)

	// (i) single-shot returns the retryable sentinel, not a broken mount.
	mounts, err := s.resolveReattachMounts(context.Background(), migName)
	var notYet *ReattachVolumeNotYetPublishedError
	if !errors.As(err, &notYet) {
		t.Fatalf("expected ReattachVolumeNotYetPublishedError on the first (unpublished) probe; got mounts=%+v err=%v", mounts, err)
	}
	if mounts != nil {
		t.Fatalf("expected nil mounts alongside the not-yet sentinel; got %+v", mounts)
	}

	// (ii) the waiter re-probes (1s cadence) and converges to the resolved leaf with nil error.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mounts, err = s.resolveReattachMountsWaiting(ctx, migName)
	if err != nil {
		t.Fatalf("resolveReattachMountsWaiting returned error after publish: %v", err)
	}
	if len(mounts) != 1 || mounts[0].ContainerPath != containerPath || mounts[0].HostTarget != wantLeaf {
		t.Fatalf("waiter did not converge to the resolved leaf: got %+v, want [{%s %s}]", mounts, containerPath, wantLeaf)
	}

	// (iii) The resolved leaf is applied via the image source-rewrite (patchCheckpointImages), not a
	// restore-side --ext-mount-map (CRIU bypasses it for the autodetected external). buildCRIURestoreArgs
	// must NOT emit an inert path-form map; the leaf must land in the patch's host-target map.
	args, err := buildCRIURestoreArgs(
		"/ckpt", "/rootfs", "/data", "/termlog", "/secrets", "/restore.log",
		"", "/var/run/netns/cni-x", "", false, mounts, nil)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs errored on resolved mounts: %v", err)
	}
	if joined := strings.Join(args, " "); strings.Contains(joined, "--ext-mount-map "+containerPath+":") {
		t.Errorf("must NOT emit an inert path-form re-attach ext-mount-map for %s (CRIU bypasses it for autodetected externals); got: %s", containerPath, joined)
	}
	if ht := reattachHostTargets(mounts); ht[containerPath] != wantLeaf {
		t.Errorf("resolved leaf must be projected into the patch host-target map: got %q, want %q", ht[containerPath], wantLeaf)
	}
}

// TestResolveKubeletVolumeHostPath_CSIMountLeaf asserts the pure mountinfo parser returns the CSI
// <pvName>/mount leaf (the bind the workload holds open), not the parent volume dir, when both are
// published as mountpoints.
func TestResolveKubeletVolumeHostPath_CSIMountLeaf(t *testing.T) {
	const uid = "b1bffab8-74e2-4a8a-ad72-f6d5d5436fcb"
	const pv = "pvc-bbf8a46b"
	base := "/var/lib/kubelet/pods/" + uid + "/volumes/kubernetes.io~csi/" + pv
	// CSI publishes both the volume dir and the /mount leaf. Field 4 (0-based) is the mountpoint.
	mountinfo := []byte(
		"100 60 0:52 / / rw,relatime shared:1 - overlay overlay rw\n" +
			"820 100 0:200 / " + base + " rw,relatime shared:400 - tmpfs tmpfs rw\n" +
			"821 820 0:201 / " + base + "/mount rw,relatime shared:401 - nfs4 server:/export rw\n")
	if got := parseKubeletMountFromMountinfo(mountinfo, uid, pv); got != base+"/mount" {
		t.Fatalf("expected CSI /mount leaf %q, got %q", base+"/mount", got)
	}
}

// TestResolveKubeletVolumeHostPath_NFSDir asserts the in-tree NFS shape (bare <pvName> dir, no
// /mount leaf) resolves to that dir.
func TestResolveKubeletVolumeHostPath_NFSDir(t *testing.T) {
	const uid = "b1bffab8-74e2-4a8a-ad72-f6d5d5436fcb"
	const pv = "pvc-bbf8a46b"
	dir := "/var/lib/kubelet/pods/" + uid + "/volumes/kubernetes.io~nfs/" + pv
	mountinfo := []byte(
		"100 60 0:52 / / rw,relatime shared:1 - overlay overlay rw\n" +
			"830 100 0:210 / " + dir + " rw,relatime shared:500 - nfs4 server:/export rw\n")
	if got := parseKubeletMountFromMountinfo(mountinfo, uid, pv); got != dir {
		t.Fatalf("expected in-tree NFS dir %q, got %q", dir, got)
	}
}

// TestResolveReattachMountsWaiting_BudgetExhausted_FailsClosed proves the "never" branch stays
// terminal: when the volume is never published and the ctx is already spent, the waiter returns a
// mount list with HostTarget=="" so buildCRIURestoreArgs fails closed with its terminal
// "reattach host target unresolved" error — never the broken 1:1 map.
func TestResolveReattachMountsWaiting_BudgetExhausted_FailsClosed(t *testing.T) {
	const migName = "postgres-live-migration"
	const replUID = "b1bffab8-74e2-4a8a-ad72-f6d5d5436fcb"
	const pvName = "pvc-bbf8a46b"
	const containerPath = "/var/lib/postgresql/data"

	orig := kubeletVolumeGlobFn
	t.Cleanup(func() { kubeletVolumeGlobFn = orig })
	kubeletVolumeGlobFn = func(_ context.Context, uid, pv string) string { return "" } // never published

	pm, pvc, replPod := reattachTestFixture(migName, replUID, pvName, containerPath)
	s := newFakeAgentServerWithCoreObjects(t, pm, pvc, replPod)

	// Already-expired ctx: the waiter must fall straight to the terminal (HostTarget=="") list.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure the deadline has passed
	mounts, err := s.resolveReattachMountsWaiting(ctx, migName)
	if err != nil {
		t.Fatalf("waiter returned a non-nil error on budget exhaustion; expected the terminal mount list: %v", err)
	}
	if len(mounts) != 1 || mounts[0].ContainerPath != containerPath || mounts[0].HostTarget != "" {
		t.Fatalf("expected a single HostTarget=='' terminal mount, got %+v", mounts)
	}
	// buildCRIURestoreArgs must fail closed on the unresolved host target, never the 1:1 map.
	if _, err := buildCRIURestoreArgs(
		"/ckpt", "/rootfs", "/data", "/termlog", "/secrets", "/restore.log",
		"", "/var/run/netns/cni-x", "", false, mounts, nil); err == nil {
		t.Fatalf("expected buildCRIURestoreArgs to fail closed on unresolved host target; got nil error")
	}
}

// TestResolveReattachMounts_InTreeNFSShapeResolvesEndToEnd is the nfs-shared gate-substrate
// regression: the near-term live gate runs postgres on the nfs-shared RWX StorageClass, whose
// kubelet publish shape is the bare in-tree /kubernetes.io~nfs/<pvName> dir (no /mount leaf). This
// pins that the label-resolved re-attach path threads the in-tree NFS host dir through end-to-end —
// resolveReattachMounts resolves the exact NFS host target via the migration-name label, and
// buildCRIURestoreArgs emits <containerPath>:<in-tree NFS dir>, never the broken 1:1 map. It fails
// if the NFS-shape resolution regresses on the substrate the gate depends on.
func TestResolveReattachMounts_InTreeNFSShapeResolvesEndToEnd(t *testing.T) {
	const migName = "postgres-live-migration"
	const replUID = "b1bffab8-74e2-4a8a-ad72-f6d5d5436fcb"
	const pvName = "pvc-bbf8a46b"
	const containerPath = "/var/lib/postgresql/data"
	// Bare in-tree NFS dir — exactly the nfs-shared publish shape (no CSI /mount leaf).
	wantHost := "/var/lib/kubelet/pods/" + replUID + "/volumes/kubernetes.io~nfs/" + pvName

	// The real parser must return EXACTLY the in-tree NFS dir from a mountinfo dump containing it.
	mountinfo := []byte(
		"100 60 0:52 / / rw,relatime shared:1 - overlay overlay rw\n" +
			"840 100 0:220 / " + wantHost + " rw,relatime shared:600 - nfs4 server:/export rw\n")
	if got := parseKubeletMountFromMountinfo(mountinfo, replUID, pvName); got != wantHost {
		t.Fatalf("parseKubeletMountFromMountinfo did not return the in-tree NFS dir: got %q, want %q", got, wantHost)
	}

	// End-to-end through the label path: glob returns the in-tree NFS dir for the labelled repl UID.
	orig := kubeletVolumeGlobFn
	t.Cleanup(func() { kubeletVolumeGlobFn = orig })
	kubeletVolumeGlobFn = func(_ context.Context, uid, pv string) string {
		if uid == replUID && pv == pvName {
			return wantHost
		}
		return ""
	}

	pm, pvc, replPod := reattachTestFixture(migName, replUID, pvName, containerPath)
	s := newFakeAgentServerWithCoreObjects(t, pm, pvc, replPod)

	mounts, err := s.resolveReattachMounts(context.Background(), migName)
	if err != nil {
		t.Fatalf("resolveReattachMounts errored on a published in-tree NFS mount: %v", err)
	}
	if len(mounts) != 1 || mounts[0].ContainerPath != containerPath || mounts[0].HostTarget != wantHost {
		t.Fatalf("in-tree NFS host target not resolved via label: got %+v, want [{%s %s}]", mounts, containerPath, wantHost)
	}

	args, err := buildCRIURestoreArgs(
		"/ckpt", "/rootfs", "/data", "/termlog", "/secrets", "/restore.log",
		"", "/var/run/netns/cni-x", "", false, mounts, nil)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs errored on the resolved in-tree NFS mount: %v", err)
	}
	// The in-tree NFS host dir is applied via the image source-rewrite (patchCheckpointImages), not a
	// restore-side --ext-mount-map (CRIU bypasses it for the autodetected external).
	if joined := strings.Join(args, " "); strings.Contains(joined, "--ext-mount-map "+containerPath+":") {
		t.Errorf("must NOT emit an inert path-form re-attach ext-mount-map for %s (CRIU bypasses it for autodetected externals); got: %s", containerPath, joined)
	}
	if ht := reattachHostTargets(mounts); ht[containerPath] != wantHost {
		t.Errorf("resolved in-tree NFS host dir must be projected into the patch host-target map: got %q, want %q", ht[containerPath], wantHost)
	}
}

// TestResolveReattachMounts_ExcludesNonTier0RWOPVC is the storage-tier gate regression: a
// PVC-backed mount that does NOT classify as Tier0 (here ReadWriteOnce — the shape a Longhorn
// dual-engine or Ceph-RBD-live volume presents) must be EXCLUDED from the re-attach set even when
// its kubelet volume dir IS published at restore time. Rewriting such a mount's recorded source to
// the destination volume dir would bypass that tier's replication/consistency handoff silently; the
// gate keeps it out of reattach_mount_paths so patch_checkpoint_script leaves it to the pre-existing
// non-Tier0 handling. Before the gate this RWO PVC was treated identically to a Tier0 RWX mount.
func TestResolveReattachMounts_ExcludesNonTier0RWOPVC(t *testing.T) {
	const migName = "postgres-live-migration"
	const replUID = "b1bffab8-74e2-4a8a-ad72-f6d5d5436fcb"
	const pvName = "pvc-bbf8a46b"
	const containerPath = "/var/lib/postgresql/data"
	published := "/var/lib/kubelet/pods/" + replUID + "/volumes/kubernetes.io~csi/" + pvName + "/mount"

	// The volume IS published — proves the exclusion is driven by the tier gate, not by an
	// unresolved host target. If the gate were absent this would resolve to a re-attach mount.
	orig := kubeletVolumeGlobFn
	t.Cleanup(func() { kubeletVolumeGlobFn = orig })
	kubeletVolumeGlobFn = func(_ context.Context, uid, pv string) string {
		if uid == replUID && pv == pvName {
			return published
		}
		return ""
	}

	pm, pvc, replPod := reattachTestFixture(migName, replUID, pvName, containerPath)
	// Override the fixture's default Tier0 RWX with ReadWriteOnce — a non-Tier0 (RWO) PVC.
	pvc.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
	s := newFakeAgentServerWithCoreObjects(t, pm, pvc, replPod)

	mounts, err := s.resolveReattachMounts(context.Background(), migName)
	if err != nil {
		t.Fatalf("resolveReattachMounts returned error for a non-Tier0 PVC (expected clean exclusion): %v", err)
	}
	if len(mounts) != 0 {
		t.Fatalf("non-Tier0 (ReadWriteOnce) PVC mount must be EXCLUDED from the re-attach set; got %+v", mounts)
	}

	// The bounded waiter must agree — a non-Tier0 PVC never enters the not-yet-published retry loop
	// and resolves immediately to an empty set.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wm, werr := s.resolveReattachMountsWaiting(ctx, migName)
	if werr != nil {
		t.Fatalf("resolveReattachMountsWaiting errored for a non-Tier0 PVC: %v", werr)
	}
	if len(wm) != 0 {
		t.Fatalf("waiter must also exclude the non-Tier0 PVC mount; got %+v", wm)
	}
}

// TestClassifyReattachTier_AccessModeMatrix pins the reattach-tier predicate to the classifier's
// rule for PVCs with no StorageClass (or an unresolvable one): ONLY a ReadWriteMany access mode is
// Tier0 RWX re-attach; RWO / ROX / RWOP and the no-access-mode case are not reattach-eligible at all.
func TestClassifyReattachTier_AccessModeMatrix(t *testing.T) {
	cases := []struct {
		name  string
		modes []corev1.PersistentVolumeAccessMode
		want  reattachTierKind
	}{
		{"rwx", []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}, reattachTierTier0RWX},
		{"rwx-among-others", []corev1.PersistentVolumeAccessMode{corev1.ReadOnlyMany, corev1.ReadWriteMany}, reattachTierTier0RWX},
		{"rwo", []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, reattachTierNone},
		{"rox", []corev1.PersistentVolumeAccessMode{corev1.ReadOnlyMany}, reattachTierNone},
		{"rwop", []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod}, reattachTierNone},
		{"none", nil, reattachTierNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pvc := &corev1.PersistentVolumeClaim{Spec: corev1.PersistentVolumeClaimSpec{AccessModes: tc.modes}}
			if got := classifyReattachTier(context.Background(), nil, pvc); got != tc.want {
				t.Errorf("classifyReattachTier(%v) = %v, want %v", tc.modes, got, tc.want)
			}
		})
	}
	if got := classifyReattachTier(context.Background(), nil, nil); got != reattachTierNone {
		t.Error("classifyReattachTier(nil) must be reattachTierNone")
	}
}

// TestClassifyReattachTier_LonghornWinsOverRWX is the regression for the mis-tagging bug: a PVC
// bound to a Longhorn-backed StorageClass (PodMotion's own longhorn-migratable class ships as
// ReadWriteMany, RWX, so it can hold the volume dual-attached during Longhorn's dual-engine live
// migration — see storage/tier1.go) must classify as Tier1-Longhorn, NOT Tier0 RWX, even though its
// access mode alone would satisfy the RWX check. This mirrors
// internal/agent/storage.classifier's real precedence (Longhorn StorageClass wins regardless of
// access mode). Before this fix, classifyReattachTier's predecessor (pvcIsTier0RWX) checked ONLY
// AccessModes and had no way to reach this distinction at all.
func TestClassifyReattachTier_LonghornWinsOverRWX(t *testing.T) {
	scName := "longhorn-migratable"
	sc := &storagev1.StorageClass{
		ObjectMeta:  metav1.ObjectMeta{Name: scName},
		Provisioner: "driver.longhorn.io",
	}
	pvc := &corev1.PersistentVolumeClaim{
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
			StorageClassName: &scName,
		},
	}
	fakeClient := newFakeAgentServerWithCoreObjects(t, sc).k8sClient
	if got := classifyReattachTier(context.Background(), fakeClient, pvc); got != reattachTierTier1Longhorn {
		t.Errorf("classifyReattachTier(Longhorn RWX PVC) = %v, want reattachTierTier1Longhorn", got)
	}
}

// TestResolveReplacementPod_NilWhenNoLabelMatch asserts the label primitive returns nil when no
// pod carries the migration-name label (caller then falls back to the status field / fail-closes).
func TestResolveReplacementPod_NilWhenNoLabelMatch(t *testing.T) {
	const migName = "redis-mig-9"
	otherPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unrelated",
			Namespace: "default",
			Labels:    map[string]string{replacementPodLabelKey: "some-other-migration"},
		},
	}
	s := newFakeAgentServerWithCoreObjects(t, otherPod)
	if got := s.resolveReplacementPod(context.Background(), migName, "default"); got != nil {
		t.Fatalf("expected nil when no pod carries the migration label; got %s", got.Name)
	}
}
