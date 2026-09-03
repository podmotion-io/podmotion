/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0417_destination_rebind_test.go — coverage for what ADR-0417 DECIDED and ADR-0419 PRESERVES:
// the --ext-mount-map token validator, the positive fstype recreatability allowlist, the
// destination-rebind emission mapping, and the stdout-injection exploit block.
//
// ADR-0419 REPLACED ADR-0417's target RESOLUTION mechanism, and §P-VERIFY #6 requires this suite to
// stop defending the defect against its own fix. Five tests were removed here, each because the
// behaviour it asserted no longer exists — not because it became inconvenient:
//
//   - _ProbeFailureIsItsOwnClass asserted `gotAttempts != 1` is a failure, i.e. it pinned FM5's
//     inversion (one transient exec deadline kills a live migration on first occurrence) as the
//     INTENDED contract. Leaving it would have made the suite actively defend the defect. §P-VERIFY #6(a).
//   - _NeverIsTerminalAndNamesTheFile and _UnresolvableContainerdRootFailsClosed asserted the
//     DestinationRebindTargetNotStagedError / DestinationRebindProbeError classes and the
//     containerd-root reconstruction. All three are deleted by ADR-0419 D6. §P-VERIFY #6(c).
//   - _ResolvesRealWriterPaths and _StagesAndProbesTerminationLog asserted the writer taxonomy and
//     the bounded probe. Their successors live in adr0419_destination_mounts_test.go and assert
//     against a FAKE NRI EVENT rather than against production's own path formula.
//   - adr0417ExpectedTargets computed its expectation with production's own filepath.Join formula,
//     so the assertion was tautological — it would have passed against any wrong path production
//     happened to build. §P-VERIFY #6(b) replaces it with a fixture whose expected Source values
//     come from the fake event.
//
// Everything ADR-0419 explicitly preserves is still asserted here, unmodified:
// TestValidateExtMountToken_RejectsHostileTokens and TestBuildCRIURestoreArgs_RejectsForgedExtMountMapToken
// (§P-VERIFY #4 / #16 both require these to keep passing), the DESTINATION-REBIND emission mapping,
// the conflicting-target rejection, and the whole fstype allowlist corpus.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/agent/nri"
)

// TestMain redirects the agent-owned restore staging tree into a writable temp dir for the whole
// package. Production writes /var/lib/podmotion/restore/<migration>/; a unit test process is not
// root and cannot mkdir /var/lib/podmotion, which would otherwise turn every restore-path test into
// a staging failure rather than exercising the logic under test.
//
// It also installs PACKAGE-DEFAULT stubs for the host-environment seams the restore path depends
// on. A unit-test process has no containerd, no kubelet pod tree, and no netns broker, so without
// these every restore-path test in the package — including ones that predate ADR-0417/ADR-0419 and
// are about something else entirely — would fail on a missing socket. Tests that actually exercise
// these paths override the seams with their own oracles, so the defaults never make a real
// assertion vacuous.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "pm-restore-staging-")
	if err != nil {
		panic(err)
	}
	restoreStagingRoot = tmp
	resolveContainerdRootDirFn = func(context.Context, string) string { return adr0417ContainerdRoot }
	// ADR-0419 D4: default to "this checkpoint demands nothing", so tests about other things do not
	// need a real checkpoint image or a python3/pycriu decode on the box.
	destinationRebindDemandSetFn = func(context.Context, string, string) (destinationRebindDemand, error) {
		return destinationRebindDemand{}, nil
	}
	// ADR-0419 D5: no containerd in a unit-test process.
	containerdRuntimeMountsOnceFn = func(context.Context, string, string) ([]nri.ContainerMount, error) { return nil, nil }
	// ADR-0419 D8: no containerd in a unit-test process; one RUNNING sandbox is the healthy shape.
	runningPodSandboxesForPodUIDFn = func(_ context.Context, podUID string) ([]string, error) {
		return []string{"sandbox-for-" + podUID}, nil
	}
	// ADR-0419 D9: the typed broker host_realpath op has no broker here. Identity is the correct
	// default — it models "this path is not a symlink", which is the real shape for every legitimate
	// target — and the tests that assert D9's escape and fail-closed legs override it explicitly.
	hostRealpathFn = func(target string) (string, error) { return target, nil }
	// sandboxIDForPodUIDFn's production implementation now issues a typed containerd round-trip,
	// which no unit-test process has. Every test that cares about sandbox resolution already
	// overrides this seam explicitly; the default just keeps tests about OTHER things working.
	sandboxIDForPodUIDFn = func(_ context.Context, podUID string) (string, error) {
		return "sandbox-for-" + podUID, nil
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

const (
	adr0417Migration = "adr0417-mig"
	adr0417Namespace = "migration-demo"
	adr0417ReplUID   = "11111111-2222-3333-4444-555555555555"
	adr0417SandboxID = "bf2767e7cafe0000cafe0000cafe0000cafe0000cafe0000cafe0000cafe0000"
	// containerdRootDir mirrors the real RKE2 value the §P-PREMISE decode found on this project's
	// standing cluster (config.toml `root = "/var/lib/rancher/rke2/agent/containerd"`).
	adr0417ContainerdRoot = "/var/lib/rancher/rke2/agent/containerd"
)

// newADR0417Server builds an AgentServer whose fake client holds the PodMigration plus a REDIS-shaped
// (zero-volume, no-PVC) replacement pod carrying the authoritative migration-name label.
//
// The workload fixture is deliberately REDIS-SHAPED: a pod with ZERO volumes and no PVC at all.
// resolveReattachMounts returns early with (nil, nil) for such a pod, so if destination-rebind
// resolution rode that path it would never run for redis. It does not — it is appended
// unconditionally on all three restore paths — and these tests are what pins that.
func newADR0417Server(t *testing.T) *AgentServer {
	t.Helper()
	scheme := newSandboxWaitScheme(t)
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: adr0417Migration, Namespace: adr0417Namespace},
		Spec:       pmv1.PodMigrationSpec{PodName: "redis", PodNamespace: adr0417Namespace},
	}
	replPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redis-r-abcdef",
			Namespace: adr0417Namespace,
			UID:       types.UID(adr0417ReplUID),
			Labels:    map[string]string{replacementPodLabelKey: adr0417Migration},
		},
		// Deliberately EMPTY: no Volumes, no VolumeMounts. This is the no-PVC workload shape.
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "redis", Image: "redis:7-alpine"}}},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pm, replPod).Build()
	return &AgentServer{k8sClient: cl}
}

// TestContainerdRootFromConfig_TopLevelKeyOnly pins the parse against the REAL RKE2-generated
// config.toml shape read off this project's standing cluster, including the decoy: a `path` key
// inside [plugins.'io.containerd.internal.v1.opt'] pointing at the same directory, and a `root`
// that must only ever be read from the top-level key space.
func TestContainerdRootFromConfig_TopLevelKeyOnly(t *testing.T) {
	const rke2Config = `# File generated by rke2. DO NOT EDIT. Use config-v3.toml.tmpl instead.
version = 3
imports = ["/var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/*.toml"]
root = "/var/lib/rancher/rke2/agent/containerd"
state = "/run/k3s/containerd"

[grpc]
  address = "/run/k3s/containerd/containerd.sock"

[plugins.'io.containerd.internal.v1.opt']
  path = "/var/lib/rancher/rke2/agent/containerd"
  root = "/should/never/be/read"
`
	if got := containerdRootFromConfig(rke2Config); got != adr0417ContainerdRoot {
		t.Errorf("containerdRootFromConfig: got %q, want %q", got, adr0417ContainerdRoot)
	}
	// A config with no top-level root at all.
	if got := containerdRootFromConfig("version = 2\n\n[plugins]\n  root = \"/nope\"\n"); got != "" {
		t.Errorf("absent top-level root must yield \"\"; got %q", got)
	}
}

// ---- S2(b): --ext-mount-map token validation ------------------------------------------------

// TestValidateExtMountToken_RejectsHostileTokens pins each rule the Security Reviewer's S2(b)
// requires, including the exact forged-token payload from the demonstrated exploit.
func TestValidateExtMountToken_RejectsHostileTokens(t *testing.T) {
	origPrefixes := extMountTokenPrefixesFn
	extMountTokenPrefixesFn = func() []string {
		return []string{"/var/lib/kubelet/pods/", filepath.Clean(restoreStagingRoot) + "/"}
	}
	defer func() { extMountTokenPrefixesFn = origPrefixes }()

	good := "/var/lib/kubelet/pods/" + adr0417ReplUID + "/etc-hosts"
	resolved := map[string]bool{good: true}

	if err := validateExtMountToken("/etc/hosts", good, resolved); err != nil {
		t.Fatalf("a legitimate agent-resolved token must validate; got %v", err)
	}

	cases := []struct {
		name, key, target, wantSubstr string
	}{
		// THE DEMONSTRATED EXPLOIT: a forged CRIU_REATTACH_EXT_MOUNT_MAP line yielding
		// `--ext-mount-map /etc/hosts:/` — the destination node's ROOT FILESYSTEM bound into the
		// restored container. Blocked because "/" was never resolved by this agent.
		{"exploit_root_filesystem_bind", "/etc/hosts", "/", "was not resolved by this agent"},
		{"unresolved_plausible_target", "/etc/hosts", "/var/lib/kubelet/pods/other/etc-hosts", "was not resolved by this agent"},
		{"key_with_colon", "/etc/ho:sts", good, "contains ':'"},
		{"key_with_newline", "/etc/hosts\nCRIU_REATTACH_EXT_MOUNT_MAP", good, "control character"},
		{"key_with_nul", "/etc/hosts\x00", good, "control character"},
		{"key_not_clean", "/etc/../etc/hosts", good, "not lexically clean"},
		{"empty_key", "", good, "empty --ext-mount-map key"},
		{"empty_target", "/etc/hosts", "", "empty --ext-mount-map host target"},
		{"relative_target", "/etc/hosts", "var/lib/kubelet/pods/x", "not an absolute path"},
		{"target_with_colon", "/etc/hosts", "/var/lib/kubelet/pods/a:b", "contains ':'"},
		{"target_with_newline", "/etc/hosts", "/var/lib/kubelet/pods/a\nb", "control character"},
		{"target_traversal", "/etc/hosts", "/var/lib/kubelet/pods/../../../etc/shadow", "not lexically clean"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExtMountToken(tc.key, tc.target, resolved)
			if err == nil {
				t.Fatalf("validateExtMountToken(%q, %q) must reject", tc.key, tc.target)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("rejection reason: got %q, want it to mention %q", err.Error(), tc.wantSubstr)
			}
		})
	}

	// Prefix rule: a target the agent DID resolve but which lies outside every allowed destination
	// tree is still rejected (defense against a resolution bug, not just a hostile image).
	outside := "/etc/shadow"
	if err := validateExtMountToken("/etc/hosts", outside, map[string]bool{outside: true}); err == nil ||
		!strings.Contains(err.Error(), "outside every allowed destination prefix") {
		t.Errorf("a resolved-but-out-of-tree target must be rejected by the prefix rule; got %v", err)
	}
}

// TestBuildCRIURestoreArgs_RejectsForgedExtMountMapToken drives the FULL argv builder with a
// reattachExtMountMap entry shaped exactly like the one the reviewer's exploit produced.
func TestBuildCRIURestoreArgs_RejectsForgedExtMountMapToken(t *testing.T) {
	origPrefixes := extMountTokenPrefixesFn
	extMountTokenPrefixesFn = func() []string {
		return []string{"/var/lib/kubelet/pods/", filepath.Clean(restoreStagingRoot) + "/"}
	}
	defer func() { extMountTokenPrefixesFn = origPrefixes }()

	forged := []ReattachExtMountMapEntry{
		{MntID: 1, Mountpoint: "/etc/hosts", ExtKey: "/etc/hosts", HostTarget: "/"},
	}
	_, err := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		restoreTerminationLogPath("test"),
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"", "/var/run/netns/cni-abc123", "", false, nil, forged)
	if err == nil {
		t.Fatal("buildCRIURestoreArgs must refuse a forged --ext-mount-map token binding the destination root filesystem")
	}
	if !strings.Contains(err.Error(), "was not resolved by this agent") {
		t.Errorf("rejection reason: got %q", err.Error())
	}
}

// TestBuildCRIURestoreArgs_DestinationRebindMapsToHostTargetNotItself pins the corrected mapping:
// the DESTINATION-REBIND loop must emit <containerPath>:<hostTarget>. The previous
// <containerPath>:<containerPath> form bound the DESTINATION NODE's own /etc/hosts into the restored
// container, and — because that loop runs first — won CRIU's first-match ext_mount_lookup over the
// correct entry emitted from the patch-script token loop.
func TestBuildCRIURestoreArgs_DestinationRebindMapsToHostTargetNotItself(t *testing.T) {
	origPrefixes := extMountTokenPrefixesFn
	extMountTokenPrefixesFn = func() []string {
		return []string{"/var/lib/kubelet/pods/", filepath.Clean(restoreStagingRoot) + "/"}
	}
	defer func() { extMountTokenPrefixesFn = origPrefixes }()

	hostTarget := "/var/lib/kubelet/pods/" + adr0417ReplUID + "/etc-hosts"
	mounts := []reattachMount{{ContainerPath: "/etc/hosts", HostTarget: hostTarget, Tier: reattachTierDestinationRebind}}
	// The patch script emits the SAME (key, target) pair for this entry (its on-disk ext_key equals
	// its mountpoint) — the builder must collapse that to one token, not emit a conflicting pair.
	tokens := []ReattachExtMountMapEntry{{MntID: 3, Mountpoint: "/etc/hosts", ExtKey: "/etc/hosts", HostTarget: hostTarget}}

	args, err := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		restoreTerminationLogPath("test"),
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"", "/var/run/netns/cni-abc123", "", false, mounts, tokens)
	if err != nil {
		t.Fatalf("buildCRIURestoreArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--ext-mount-map /etc/hosts:"+hostTarget) {
		t.Errorf("expected --ext-mount-map /etc/hosts:%s; got: %s", hostTarget, joined)
	}
	if strings.Contains(joined, "--ext-mount-map /etc/hosts:/etc/hosts") {
		t.Errorf("the self-mapping form binds the DESTINATION NODE's own /etc/hosts into the container; got: %s", joined)
	}
	if n := strings.Count(joined, "--ext-mount-map /etc/hosts:"); n != 1 {
		t.Errorf("expected exactly one --ext-mount-map entry for /etc/hosts (byte-identical duplicates collapse); got %d in: %s", n, joined)
	}
}

// TestBuildCRIURestoreArgs_ConflictingExtMountTargetsRejected: two DIFFERENT targets for one key
// would silently resolve to whichever CRIU's first-match lookup saw first.
func TestBuildCRIURestoreArgs_ConflictingExtMountTargetsRejected(t *testing.T) {
	origPrefixes := extMountTokenPrefixesFn
	extMountTokenPrefixesFn = func() []string {
		return []string{"/var/lib/kubelet/pods/", filepath.Clean(restoreStagingRoot) + "/"}
	}
	defer func() { extMountTokenPrefixesFn = origPrefixes }()

	a := "/var/lib/kubelet/pods/" + adr0417ReplUID + "/etc-hosts"
	b := "/var/lib/kubelet/pods/" + adr0417ReplUID + "/other-hosts"
	mounts := []reattachMount{
		{ContainerPath: "/etc/hosts", HostTarget: a, Tier: reattachTierDestinationRebind},
		{ContainerPath: "/other", HostTarget: b, Tier: reattachTierDestinationRebind},
	}
	tokens := []ReattachExtMountMapEntry{{MntID: 3, Mountpoint: "/etc/hosts", ExtKey: "/etc/hosts", HostTarget: b}}
	_, err := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		restoreTerminationLogPath("test"),
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"", "/var/run/netns/cni-abc123", "", false, mounts, tokens)
	if err == nil || !strings.Contains(err.Error(), "conflicting --ext-mount-map targets") {
		t.Fatalf("expected a conflicting-target rejection; got %v", err)
	}
}

// ---- Condition 1: positive fstype allowlist ---------------------------------------------------

// adr0417FstypeCorpusGenPy writes a mountpoints image with an overlay root plus ONE external entry
// at /mnt/probe carrying the fstype code under test and a literal ext_key. Parameterized so a single
// generator covers every code in and out of CRIU 4.2's fstypes[] table.
const adr0417FstypeCorpusGenPy = `
import sys, os
import pycriu
d, fstype = sys.argv[1], int(sys.argv[2])
mnts = [
    {'fstype': 17, 'mnt_id': 1, 'root_dev': 0, 'parent_mnt_id': 0, 'flags': 0,
     'root': '/', 'mountpoint': '/', 'source': 'overlay', 'options': '', 'sb_flags': 0},
    {'fstype': fstype, 'mnt_id': 2, 'root_dev': 0, 'parent_mnt_id': 1, 'flags': 0,
     'root': '/src/node/only', 'mountpoint': '/mnt/probe', 'source': '/src/node/only',
     'options': '', 'sb_flags': 0, 'ext_key': '/mnt/probe'},
]
with open(os.path.join(d, 'mountpoints-10.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': mnts}, f)
print('CORPUS_OK')
`

func writeADR0417FstypeCorpus(t *testing.T, pypath string, extraEnv []string, ckptDir string, fstype int) {
	t.Helper()
	genPath := filepath.Join(t.TempDir(), "adr0417-fstype-gen.py")
	if err := os.WriteFile(genPath, []byte(adr0417FstypeCorpusGenPy), 0o600); err != nil {
		t.Fatalf("write fstype corpus generator: %v", err)
	}
	cmd := exec.Command("python3", genPath, ckptDir, strconv.Itoa(fstype))
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "CORPUS_OK") {
		t.Fatalf("generate fstype=%d corpus: %v\noutput: %s", fstype, err, out)
	}
}

// TestPatchCheckpointImages_ADR0417_FstypeAllowlist is the Condition-1 assertion the previous
// implementation had no coverage for at all: an IN-TABLE-BUT-NOT-RECREATABLE fstype must classify
// DESTINATION-REBIND, not RECREATABLE.
//
// The non-recreatable codes below are read straight out of CRIU 4.2's own fstypes[] array, decoded
// from the shipped binary's DWARF — not from the mnt.proto enum, which lists table MEMBERSHIP and
// says nothing about construct-and-fill capability. FSTYPE__AUTO (16) is the sharpest case: its row
// carries no callbacks at all, and FUSE (15) is sharper still — its .dump and .restore are literally
// always_fail, so the old `fstype != 0` predicate routed it to the one branch CRIU guarantees will
// fail. Codes 20 and 99 stand for a filesystem a FUTURE CRIU numbers outside today's table (which is
// exactly what btrfs/nfs/zfs are): the allowlist fails them closed with no code change, where the
// denylist would have silently internalized them.
func TestPatchCheckpointImages_ADR0417_FstypeAllowlist(t *testing.T) {
	recreatable := []struct {
		code int
		name string
	}{
		{1, "PROC"}, {2, "SYSFS"}, {3, "DEVTMPFS"}, {4, "BINFMT_MISC"},
		{5, "TMPFS"}, {6, "DEVPTS"}, {14, "MQUEUE"},
	}
	notRecreatable := []struct {
		code int
		name string
	}{
		{0, "UNSUPPORTED (ext4/xfs/btrfs — btrfs's own fstypes[] row has code 0)"},
		{7, "SIMFS (no callbacks; a real container-root filesystem)"},
		{8, "PSTORE (dump_empty_fs only, no restore)"},
		{9, "SECURITYFS (no callbacks; host-global)"},
		{10, "FUSECTL (fusectl_dump only, no restore)"},
		{11, "DEBUGFS (parse only, no restore)"},
		{12, "CGROUP (parse/sb_equal only)"},
		{13, "AUFS (parse only; union fs over source-node branches)"},
		{15, "FUSE (.dump and .restore are always_fail)"},
		{16, "AUTO/auto_cr (all callbacks NULL)"},
		{17, "OVERLAYFS (parse only; union fs over source-node lower/upper)"},
		{18, "AUTOFS (no restore; automounter daemon is source-node-local)"},
		{19, "TRACEFS (parse only, no restore; host-global)"},
		{23, "CGROUP2 (parse/sb_equal only)"},
		{20, "outside CRIU 4.2's table entirely (a future non-recreatable fs)"},
		{99, "far outside the table"},
	}

	for _, tc := range recreatable {
		t.Run("recreatable_"+tc.name, func(t *testing.T) {
			pypath, extraEnv := pycriuEnv(t)
			ckptDir := t.TempDir()
			writeADR0417FstypeCorpus(t, pypath, extraEnv, ckptDir, tc.code)
			// ADR-0420 D1: recreatability is necessary but NOT SUFFICIENT. For the two
			// construct-and-fill fstypes (DEVTMPFS=3, TMPFS=5) the classifier now additionally
			// requires the checkpoint to actually CARRY the mount's content, because internalizing a
			// contentless one hands CRIU an empty superblock to fill from an image that does not
			// exist and tmpfs_restore fails silently. This corpus entry has root_dev=0, so staging
			// tmpfs-dev-0.tar.gz.img is what makes it the /dev/shm shape — a recreatable mount whose
			// content IS in the checkpoint — and the assertions below are unchanged for it.
			// ADR-0420's own suite covers the contentless case in every direction.
			if tc.code == 3 || tc.code == 5 {
				stageTmpfsContentImage(t, ckptDir, "tmpfs-dev-0.tar.gz.img")
			}
			// No host target supplied: a RECREATABLE mount does not need one, so this must succeed.
			if _, _, err := patchCheckpointImages(ckptDir, nil, nil, nil, nil); err != nil {
				t.Fatalf("fstype %d (%s) must classify RECREATABLE and internalize without a destination target; got %v", tc.code, tc.name, err)
			}
			entries := readMountpointsEntries(t, pypath, extraEnv, ckptDir)
			e := findMountEntry(entries, "/mnt/probe")
			if e == nil {
				t.Fatal("/mnt/probe missing from the patched image")
			}
			if k, ok := e["ext_key"]; ok && k != nil && k != "" {
				t.Errorf("fstype %d (%s): RECREATABLE must have ext_key cleared; got %v", tc.code, tc.name, k)
			}
			if root, _ := e["root"].(string); root != "/" {
				t.Errorf("fstype %d (%s): RECREATABLE must have root rewritten to \"/\"; got %q", tc.code, tc.name, root)
			}
		})
	}

	for _, tc := range notRecreatable {
		t.Run("not_recreatable_"+strconv.Itoa(tc.code), func(t *testing.T) {
			pypath, extraEnv := pycriuEnv(t)

			// (a) With no destination target: fail closed. Under the old `fstype != 0` denylist every
			// one of these (except code 0) silently internalized instead.
			ckptA := t.TempDir()
			writeADR0417FstypeCorpus(t, pypath, extraEnv, ckptA, tc.code)
			_, _, err := patchCheckpointImages(ckptA, nil, nil, nil, nil)
			if err == nil {
				t.Fatalf("fstype %d (%s) is not construct-and-fill — it must NOT be internalized; expected a fail-closed hard-stop", tc.code, tc.name)
			}
			var unresolved *ExternalMountUnresolvedError
			if !errors.As(err, &unresolved) || unresolved.Reason != "destination_rebind_target_unresolved" {
				t.Fatalf("fstype %d (%s): want ExternalMountUnresolvedError/destination_rebind_target_unresolved; got %v", tc.code, tc.name, err)
			}

			// (b) With a destination target: DESTINATION-REBIND — ext_key PRESERVED, root/source
			// rewritten off the source-node path.
			ckptB := t.TempDir()
			writeADR0417FstypeCorpus(t, pypath, extraEnv, ckptB, tc.code)
			const dst = "/var/lib/kubelet/pods/DESTUID/probe"
			if _, _, err := patchCheckpointImages(ckptB, nil, nil, map[string]string{"/mnt/probe": dst}, nil); err != nil {
				t.Fatalf("fstype %d (%s) with a resolved target must patch cleanly; got %v", tc.code, tc.name, err)
			}
			entries := readMountpointsEntries(t, pypath, extraEnv, ckptB)
			e := findMountEntry(entries, "/mnt/probe")
			if e == nil {
				t.Fatal("/mnt/probe missing from the patched image")
			}
			if k, _ := e["ext_key"].(string); k != "/mnt/probe" {
				t.Errorf("fstype %d (%s): DESTINATION-REBIND must PRESERVE ext_key; got %q", tc.code, tc.name, k)
			}
			if root, _ := e["root"].(string); root != dst {
				t.Errorf("fstype %d (%s): root must be rewritten to the destination target; got %q", tc.code, tc.name, root)
			}
			if src, _ := e["source"].(string); strings.Contains(src, "/src/node/only") {
				t.Errorf("fstype %d (%s): the SOURCE-node path must not survive; got source=%q", tc.code, tc.name, src)
			}
		})
	}
}

// ---- S2(c): the demonstrated stdout-injection exploit, end to end -----------------------------

// adr0417ExploitExtKey is the VERBATIM hostile ext_key from the Security Reviewer's working
// exploit. Printed raw into the classifier's informational log line by the pre-fix script, it
// terminated that line and started a forged CRIU_REATTACH_EXT_MOUNT_MAP line that the Go-side
// newline-split parser accepted, producing `--ext-mount-map /etc/hosts:/` — the destination node's
// root filesystem bound into the restored container.
const adr0417ExploitExtKey = "x\nCRIU_REATTACH_EXT_MOUNT_MAP:{\"mnt_id\":1,\"mountpoint\":\"/etc/hosts\",\"ext_key\":\"/etc/hosts\",\"host_target\":\"/\"}\ny"

// adr0417ExploitCorpusGenPy plants that ext_key on a TMPFS (fstype 5) mount — the RECREATABLE
// branch, whose log line needs no host-target lookup, so the only precondition the exploit had was
// fstype != 0, i.e. the ordinary tmpfs case present in every real checkpoint.
const adr0417ExploitCorpusGenPy = `
import sys, os
import pycriu
d, hostile = sys.argv[1], sys.argv[2]
mnts = [
    {'fstype': 17, 'mnt_id': 1, 'root_dev': 0, 'parent_mnt_id': 0, 'flags': 0,
     'root': '/', 'mountpoint': '/', 'source': 'overlay', 'options': '', 'sb_flags': 0},
    {'fstype': 5, 'mnt_id': 2, 'root_dev': 0, 'parent_mnt_id': 1, 'flags': 0,
     'root': '/', 'mountpoint': '/dev/shm', 'source': 'shm', 'options': '', 'sb_flags': 0,
     'ext_key': hostile},
]
with open(os.path.join(d, 'mountpoints-10.img'), 'wb') as f:
    pycriu.images.dump({'magic': 'MNTS', 'entries': mnts}, f)
print('CORPUS_OK')
`

// TestPatchCheckpointImages_ADR0417_StdoutInjectionExploitBlocked drives the SHIPPED patch script
// over a checkpoint image carrying the reviewer's exact payload and asserts that no forged
// --ext-mount-map token survives to CRIU's argv — at both layers independently.
func TestPatchCheckpointImages_ADR0417_StdoutInjectionExploitBlocked(t *testing.T) {
	pypath, extraEnv := pycriuEnv(t)
	ckptDir := t.TempDir()
	genPath := filepath.Join(t.TempDir(), "adr0417-exploit-gen.py")
	if err := os.WriteFile(genPath, []byte(adr0417ExploitCorpusGenPy), 0o600); err != nil {
		t.Fatalf("write exploit corpus generator: %v", err)
	}
	cmd := exec.Command("python3", genPath, ckptDir, adr0417ExploitExtKey)
	cmd.Env = append(extraEnv, "PYTHONPATH="+pypath)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "CORPUS_OK") {
		t.Fatalf("generate exploit corpus: %v\noutput: %s", err, out)
	}
	// ADR-0420 D1: the exploit's only precondition is that the hostile ext_key reaches the
	// RECREATABLE branch's log line, which is now additionally gated on the checkpoint carrying the
	// mount's content (corpus root_dev=0). Staging it keeps this test pointed at the INJECTION
	// surface rather than accidentally re-testing the content gate — without it the entry would
	// take the DESTINATION-REBIND branch and the exploit's actual target would go unexercised.
	stageTmpfsContentImage(t, ckptDir, "tmpfs-dev-0.tar.gz.img")

	_, tokens, err := patchCheckpointImages(ckptDir, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("patchCheckpointImages on the exploit corpus: %v", err)
	}

	// LAYER 1 (script side): the hostile bytes are json.dumps-encoded / control-char-stripped, so
	// the forged line never exists on stdout and the Go parser cannot see a token at all.
	for _, tk := range tokens {
		if tk.HostTarget == "/" {
			t.Fatalf("stdout injection succeeded: parsed a forged token %+v — the payload reached the Go-side parser", tk)
		}
	}

	// LAYER 2 (argv side): even if a token WERE parsed, buildCRIURestoreArgs must refuse it. Feed the
	// exact token the pre-fix pipeline produced, verbatim.
	origPrefixes := extMountTokenPrefixesFn
	extMountTokenPrefixesFn = func() []string {
		return []string{"/var/lib/kubelet/pods/", filepath.Clean(restoreStagingRoot) + "/"}
	}
	defer func() { extMountTokenPrefixesFn = origPrefixes }()
	forged := []ReattachExtMountMapEntry{{MntID: 1, Mountpoint: "/etc/hosts", ExtKey: "/etc/hosts", HostTarget: "/"}}
	args, argErr := buildCRIURestoreArgs(
		"/run/podmotion/checkpoints/test/final",
		"/var/lib/podmotion/restore/test/bundle/rootfs",
		"/var/lib/podmotion/restore/test/data",
		restoreTerminationLogPath("test"),
		"/var/lib/podmotion/restore/test/secrets",
		"/run/podmotion/checkpoints/test/final/restore.log",
		"", "/var/run/netns/cni-abc123", "", false, nil, forged)
	if argErr == nil {
		t.Fatalf("buildCRIURestoreArgs accepted the forged token; argv: %s", strings.Join(args, " "))
	}
	if strings.Contains(strings.Join(args, " "), "--ext-mount-map /etc/hosts:/") {
		t.Fatal("the destination node's root filesystem reached CRIU argv")
	}
}
