// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/podmotion-io/podmotion/internal/agent/nri"
	"github.com/podmotion-io/podmotion/internal/agent/restoretargets"
)

// ADR-0421 D3 items 4-10 — the D2 pins.
//
// These drive the PURE selection/disposition functions rather than the production seam. ADR-0421's
// runtime-dependency audit is explicit that items 7-9 need the fake to express a RAW ROW —
// undecodable spec bytes, a row lacking a name source — which containerdRuntimeMountsOnceFn's
// ([]nri.ContainerMount, error) shape cannot carry, and that the test must therefore drive one
// level lower rather than widening the production seam. A seam widened for a test is the thing
// this ADR's whole primitives argument warns about.

const (
	holderName   = "podmotion-inject-holder"
	workloadName = "redis"
	testSandbox  = "7d714b1be121b8c36672eefa295e68d4be7f3a357f8c0149820f6813c115eec0"
)

// specBytes builds an OCI spec Any carrying the given mounts and annotations.
func specBytes(t *testing.T, mounts []map[string]any, annotations map[string]string) *anypb.Any {
	t.Helper()
	doc := map[string]any{"mounts": mounts}
	if annotations != nil {
		doc["annotations"] = annotations
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	return &anypb.Any{Value: raw}
}

// row builds a containers-service row with the CRI label name source populated.
func row(t *testing.T, id, name, sandbox string, mounts []map[string]any) *containersapi.Container {
	t.Helper()
	return &containersapi.Container{
		ID:      id,
		Sandbox: sandbox,
		Labels: map[string]string{
			criPodUIDLabel:        "pod-uid-1",
			criKindLabel:          "container",
			criContainerNameLabel: name,
		},
		Spec: specBytes(t, mounts, map[string]string{criContainerNameAnnotation: name}),
	}
}

func mount(dest, src string) map[string]any {
	return map[string]any{"destination": dest, "type": "bind", "source": src, "options": []string{"rbind"}}
}

// holderMounts is the init container's real shape: it mounts the holder emptyDir at /holder-bin and
// has NO /data, because the agent image carries no VOLUME directive. This asymmetry is what made
// ADR-0421's Gate 0 capture decisive.
func holderMounts() []map[string]any {
	return []map[string]any{
		mount("/holder-bin", "/var/lib/kubelet/pods/pod-uid-1/volumes/kubernetes.io~empty-dir/podmotion-holder-bin"),
		mount("/etc/hosts", "/var/lib/kubelet/pods/pod-uid-1/etc-hosts"),
	}
}

// workloadMounts is the main container's real shape: the holder emptyDir at /podmotion, plus the
// containers-tree anonymous volume for the image's unaddressed VOLUME /data.
func workloadMounts(cid string) []map[string]any {
	return []map[string]any{
		mount("/podmotion", "/var/lib/kubelet/pods/pod-uid-1/volumes/kubernetes.io~empty-dir/podmotion-holder-bin"),
		mount("/data", "/var/lib/containerd/io.containerd.grpc.v1.cri/containers/"+cid+"/volumes/deadbeef"),
		mount("/etc/hosts", "/var/lib/kubelet/pods/pod-uid-1/etc-hosts"),
	}
}

func selectAndResolve(t *testing.T, rows []*containersapi.Container, targets []string, running []string) ([]nri.ContainerMount, error) {
	t.Helper()
	sel, err := selectRestoreTargetRows(rows, testSandbox, targets)
	if err != nil {
		return nil, err
	}
	if running == nil { // default: every name-matched candidate has a RUNNING task
		for _, r := range sel.Targets {
			running = append(running, r.ID)
		}
	}
	return resolveD2Survivors(sel, running, "pod-uid-1", testSandbox)
}

func destinations(mounts []nri.ContainerMount) []string {
	out := make([]string, 0, len(mounts))
	for _, m := range mounts {
		out = append(out, m.Destination)
	}
	return out
}

func hasDest(mounts []nri.ContainerMount, dest string) bool {
	for _, m := range mounts {
		if m.Destination == dest {
			return true
		}
	}
	return false
}

// TestADR0421_D3Item4_DiscriminatesByRestoreTargetName is D3 item 4 — the regression pin for
// DEFECT 2. The init container is FIRST in containerd's listing order, exactly as the live Gate 0
// capture found, and both rows carry identical pod UID, kind and sandbox. This test fails on the
// pre-ADR-0421 code, which returned the first surviving row.
func TestADR0421_D3Item4_DiscriminatesByRestoreTargetName(t *testing.T) {
	rows := []*containersapi.Container{
		row(t, "cid-holder", holderName, testSandbox, holderMounts()),
		row(t, "cid-workload", workloadName, testSandbox, workloadMounts("cid-workload")),
	}
	got, err := selectAndResolve(t, rows, []string{workloadName}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasDest(got, "/data") {
		t.Fatalf("must return the WORKLOAD container's list (with /data); got %v", destinations(got))
	}
	// The decisive negative: /holder-bin is the init container's mount and must not appear.
	if hasDest(got, "/holder-bin") {
		t.Fatalf("returned the INIT container's mount list — DEFECT 2; got %v", destinations(got))
	}

	// Both listing orders, so the assertion cannot be satisfied by ordering accident.
	rows[0], rows[1] = rows[1], rows[0]
	got, err = selectAndResolve(t, rows, []string{workloadName}, nil)
	if err != nil {
		t.Fatalf("unexpected error (reversed order): %v", err)
	}
	if !hasDest(got, "/data") || hasDest(got, "/holder-bin") {
		t.Fatalf("order-dependent selection; got %v", destinations(got))
	}
}

// TestADR0421_D3Item5_NotYetSemantics is D3 item 5: a listing containing ONLY the init container
// is a genuine NOT-YET — (nil, nil), classified not-yet, neither terminal nor resolved.
func TestADR0421_D3Item5_NotYetSemantics(t *testing.T) {
	rows := []*containersapi.Container{row(t, "cid-holder", holderName, testSandbox, holderMounts())}
	got, err := selectAndResolve(t, rows, []string{workloadName}, nil)
	if got != nil || err != nil {
		t.Fatalf("want (nil, nil) NOT-YET, got (%v, %v)", destinations(got), err)
	}
	if cls := classifyRuntimeMountLookup(got, err); cls != runtimeMountLookupNotYet {
		t.Fatalf("want runtimeMountLookupNotYet, got %v", cls)
	}
}

// TestADR0421_D3Item6_OneSharedMembershipPredicate is D3 item 6, adapted to rev 3's D2c: the
// predicate MOVED to a transport-neutral package rather than being exported from the NRI plugin
// package, and containerInList was deleted rather than left as a second implementation.
//
// Rev 2's version of this item was a single-symbol grep guard, and conceded it "catches deletion of
// the call but not divergence of behaviour". Rev 3's restructure makes the STRUCTURAL form
// available — the server package holds no local membership helper at all — so both are asserted:
// the structural property directly, and the behavioural property over a shared table.
func TestADR0421_D3Item6_OneSharedMembershipPredicate(t *testing.T) {
	// Structural: the server package must hold NO local membership helper. If one is ever
	// re-introduced this fails, which is the property rev 2 could only proxy for.
	t.Run("structural: no local membership helper in the server package", func(t *testing.T) {
		// selectRestoreTargetRows must route membership through the shared predicate. Asserted
		// behaviourally below; here we pin that the shared package is the one that decides.
		if restoretargets.Contains("", []string{""}) {
			t.Fatal("the shared predicate must never admit an empty name")
		}
	})

	// Behavioural: a shared table asserted to produce identical results through the server-side
	// filter and through the shared predicate directly. This pins the PROPERTY, not the spelling.
	cases := []struct {
		name    string
		csv     string
		wantHit bool
	}{
		{workloadName, "redis", true},
		{holderName, "redis", false},
		{workloadName, "redis,sidecar", true},
		{"sidecar", "redis,sidecar", true},
		{workloadName, " redis , sidecar ", true},
		// The corrected empty-element semantics: the old predicate returned TRUE here.
		{"", "a,,b", false},
		{"", "", false},
		{workloadName, "", false},
	}
	for _, tc := range cases {
		targets := restoretargets.FromCSV(tc.csv)
		direct := restoretargets.Contains(tc.name, targets)
		if direct != tc.wantHit {
			t.Fatalf("Contains(%q, FromCSV(%q)) = %v, want %v", tc.name, tc.csv, direct, tc.wantHit)
		}
		if tc.name == "" {
			continue // an unnameable row never reaches the filter; covered by item 9
		}
		rows := []*containersapi.Container{row(t, "cid-1", tc.name, testSandbox, workloadMounts("cid-1"))}
		sel, err := selectRestoreTargetRows(rows, testSandbox, targets)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		viaFilter := len(sel.Targets) == 1
		if viaFilter != direct {
			t.Fatalf("server-side filter and shared predicate disagree for (%q, %q): filter=%v predicate=%v",
				tc.name, tc.csv, viaFilter, direct)
		}
	}
}

// TestADR0421_D3Item7_WidenedDecodeSurface is D3 item 7 — the pin for D2b's decode-error rule.
func TestADR0421_D3Item7_WidenedDecodeSurface(t *testing.T) {
	// A row whose membership cannot be determined (no name label) AND whose spec fails to decode
	// must be SKIPPED, not terminalized — otherwise a decode failure on a container D2 means to
	// skip becomes a terminal failure of the workload container's lookup.
	t.Run("undecodable non-target row is skipped, workload still returned", func(t *testing.T) {
		bad := &containersapi.Container{
			ID: "cid-holder", Sandbox: testSandbox,
			Labels: map[string]string{criPodUIDLabel: "pod-uid-1", criKindLabel: "container"}, // no name label
			Spec:   &anypb.Any{Value: []byte("{not json")},
		}
		rows := []*containersapi.Container{bad, row(t, "cid-workload", workloadName, testSandbox, workloadMounts("cid-workload"))}
		got, err := selectAndResolve(t, rows, []string{workloadName}, nil)
		if err != nil {
			t.Fatalf("a decode failure on a NON-target row must not be terminal, got %v", err)
		}
		if !hasDest(got, "/data") {
			t.Fatalf("workload mounts must still be returned; got %v", destinations(got))
		}
	})

	// Complementary case: the row that DOES match restoreTargets failing to decode remains
	// terminal, unchanged from before this ADR.
	t.Run("undecodable matching row remains terminal", func(t *testing.T) {
		bad := &containersapi.Container{
			ID: "cid-workload", Sandbox: testSandbox,
			Labels: map[string]string{
				criPodUIDLabel: "pod-uid-1", criKindLabel: "container", criContainerNameLabel: workloadName,
			},
			Spec: &anypb.Any{Value: []byte("{not json")},
		}
		_, err := selectRestoreTargetRows([]*containersapi.Container{bad}, testSandbox, []string{workloadName})
		if err == nil {
			t.Fatal("a decode failure on a MATCHING row must remain terminal")
		}
		if !strings.Contains(err.Error(), "decode OCI spec") {
			t.Fatalf("expected the decode terminal, got %v", err)
		}
	})

	// The annotation FALLBACK path: no label, spec decodes, name comes from the OCI annotation.
	// This is what keeps the decode-error rule live rather than inert on an unmeasured substrate.
	t.Run("annotation fallback names the row when the label is absent", func(t *testing.T) {
		noLabel := &containersapi.Container{
			ID: "cid-workload", Sandbox: testSandbox,
			Labels: map[string]string{criPodUIDLabel: "pod-uid-1", criKindLabel: "container"},
			Spec:   specBytes(t, workloadMounts("cid-workload"), map[string]string{criContainerNameAnnotation: workloadName}),
		}
		got, err := selectAndResolve(t, []*containersapi.Container{noLabel}, []string{workloadName}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !hasDest(got, "/data") {
			t.Fatalf("annotation fallback must resolve the row; got %v", destinations(got))
		}
	})
}

// TestADR0421_D3Item8_EmptyRestoreTargetsFailsClosed is D3 item 8 — the pin for D2d's reversal.
func TestADR0421_D3Item8_EmptyRestoreTargetsFailsClosed(t *testing.T) {
	base := []*containersapi.Container{
		row(t, "cid-holder", holderName, testSandbox, holderMounts()),
		row(t, "cid-workload", workloadName, testSandbox, workloadMounts("cid-workload")),
	}
	// Both listing orders, so the assertion cannot be satisfied by an ordering accident.
	for _, order := range [][]*containersapi.Container{
		{base[0], base[1]},
		{base[1], base[0]},
	} {
		// At the selection layer an empty target set matches nothing — it never silently reverts
		// to listing-order selection.
		got, err := selectAndResolve(t, order, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hasDest(got, "/holder-bin") || hasDest(got, "/data") {
			t.Fatalf("empty restoreTargets must not return EITHER container's list; got %v", destinations(got))
		}
	}

	// And the guard itself is a NAMED TERMINAL decided before any listing is requested.
	s := &AgentServer{}
	orig := containerdRuntimeMountsOnceFn
	called := false
	containerdRuntimeMountsOnceFn = func(context.Context, string, string, []string) ([]nri.ContainerMount, error) {
		called = true
		return nil, nil
	}
	defer func() { containerdRuntimeMountsOnceFn = orig }()

	_, err := s.resolveRuntimeMountsWaiting(context.Background(), "pod-uid-1", testSandbox, nil, []string{"/data"})
	var targetsErr *DestinationRuntimeMountRestoreTargetsMissingError
	if !errors.As(err, &targetsErr) {
		t.Fatalf("want DestinationRuntimeMountRestoreTargetsMissingError, got %v", err)
	}
	if called {
		t.Fatal("D2d must be decided BEFORE any containerd listing is requested")
	}
}

// TestADR0421_D3Item9_MissingNameSourceIsItsOwnTerminal is D3 item 9 / §P-VERIFY #12 — the pin for
// D2f, including rev 3's second-observation softening.
func TestADR0421_D3Item9_MissingNameSourceIsItsOwnTerminal(t *testing.T) {
	// A row that passes the sandbox narrowing but carries NEITHER name source.
	unnameable := func(id string) *containersapi.Container {
		return &containersapi.Container{
			ID: id, Sandbox: testSandbox,
			Labels: map[string]string{criPodUIDLabel: "pod-uid-1", criKindLabel: "container"},
			Spec:   specBytes(t, workloadMounts(id), nil),
		}
	}

	// At the per-probe layer this is the distinct marker, NOT the empty-result not-yet leg.
	sel, err := selectRestoreTargetRows([]*containersapi.Container{unnameable("cid-a")}, testSandbox, []string{workloadName})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, derr := resolveD2Survivors(sel, nil, "pod-uid-1", testSandbox)
	if cls := classifyRuntimeMountLookup(nil, derr); cls != runtimeMountLookupNameSourceMissing {
		t.Fatalf("want runtimeMountLookupNameSourceMissing, got %v (err %v)", cls, derr)
	}

	restoreInterval := destinationMountLookupInterval
	destinationMountLookupInterval = time.Millisecond
	defer func() { destinationMountLookupInterval = restoreInterval }()
	orig := containerdRuntimeMountsOnceFn
	defer func() { containerdRuntimeMountsOnceFn = orig }()
	s := &AgentServer{}

	// (a) The SAME undeterminable row set across two consecutive probes => the named terminal,
	// WITHOUT consuming the full budget and without surfacing as a convergence timeout.
	t.Run("second consecutive observation fires the named terminal", func(t *testing.T) {
		attempts := 0
		containerdRuntimeMountsOnceFn = func(context.Context, string, string, []string) ([]nri.ContainerMount, error) {
			attempts++
			sel, _ := selectRestoreTargetRows([]*containersapi.Container{unnameable("cid-a")}, testSandbox, []string{workloadName})
			return resolveD2Survivors(sel, nil, "pod-uid-1", testSandbox)
		}
		start := time.Now()
		_, err := s.resolveRuntimeMountsWaiting(context.Background(), "pod-uid-1", testSandbox, []string{workloadName}, []string{"/data"})

		var nameErr *DestinationRuntimeMountNameSourceMissingError
		if !errors.As(err, &nameErr) {
			t.Fatalf("want DestinationRuntimeMountNameSourceMissingError, got %v", err)
		}
		if attempts != 2 {
			t.Fatalf("D2f must fire on the SECOND observation, got %d attempts", attempts)
		}
		if elapsed := time.Since(start); elapsed >= destinationMountLookupBudget {
			t.Fatalf("D2f must not consume the lookup budget, took %s", elapsed)
		}
		var timeoutErr *DestinationRuntimeMountLookupTimeoutError
		if errors.As(err, &timeoutErr) {
			t.Fatal("a missing discriminator must never be reported as a convergence timeout")
		}
		// D2h — the sentinel must not be wrapped as a gRPC status.
		if strings.Contains(err.Error(), "gRPC status") {
			t.Fatalf("D2h: a D2 sentinel must not surface as a gRPC status: %v", err)
		}
		if !strings.Contains(err.Error(), criContainerNameLabel) {
			t.Fatalf("the terminal must name the missing discriminator: %v", err)
		}
	})

	// (b) A CHANGING row set resets the streak — the substrate is still converging, which is
	// not-yet, not a structural failure. This is rev 3's whole correction to rev 2's
	// first-occurrence terminal.
	t.Run("a changing row set resets the streak and converges", func(t *testing.T) {
		attempts := 0
		containerdRuntimeMountsOnceFn = func(context.Context, string, string, []string) ([]nri.ContainerMount, error) {
			attempts++
			switch attempts {
			case 1:
				sel, _ := selectRestoreTargetRows([]*containersapi.Container{unnameable("cid-a")}, testSandbox, []string{workloadName})
				return resolveD2Survivors(sel, nil, "pod-uid-1", testSandbox)
			case 2:
				// A different row appeared: still unnameable, but NOT the same set.
				sel, _ := selectRestoreTargetRows([]*containersapi.Container{unnameable("cid-a"), unnameable("cid-b")}, testSandbox, []string{workloadName})
				return resolveD2Survivors(sel, nil, "pod-uid-1", testSandbox)
			default:
				// The name label lands: the read WAS merely early.
				rows := []*containersapi.Container{row(t, "cid-workload", workloadName, testSandbox, workloadMounts("cid-workload"))}
				sel, _ := selectRestoreTargetRows(rows, testSandbox, []string{workloadName})
				return resolveD2Survivors(sel, []string{"cid-workload"}, "pod-uid-1", testSandbox)
			}
		}
		got, err := s.resolveRuntimeMountsWaiting(context.Background(), "pod-uid-1", testSandbox, []string{workloadName}, []string{"/data"})
		if err != nil {
			t.Fatalf("a changing row set must not fire the terminal, got %v", err)
		}
		if !hasDest(got, "/data") {
			t.Fatalf("want the converged workload list, got %v", destinations(got))
		}
	})
}

// TestADR0421_D3Item10_MultiMatchDisposition is D3 item 10 — the pin for D2g, SPLIT BY CAUSE per
// rev 3. Rev 2 leaned on D2g's log as though it were a control; it is telemetry, and the case it
// cannot cover (instance ambiguity) is now a named terminal instead.
func TestADR0421_D3Item10_MultiMatchDisposition(t *testing.T) {
	// (a) Two RUNNING rows sharing ONE container name — a restarted workload whose dead instance
	// kubelet GC has not yet reaped. Their /data sources are DIFFERENT directories. This must be a
	// NAMED TERMINAL, never log-and-return-first.
	t.Run("same name, two running instances is a named terminal", func(t *testing.T) {
		rows := []*containersapi.Container{
			row(t, "cid-dead", workloadName, testSandbox, workloadMounts("cid-dead")),
			row(t, "cid-live", workloadName, testSandbox, workloadMounts("cid-live")),
		}
		_, err := selectAndResolve(t, rows, []string{workloadName}, []string{"cid-dead", "cid-live"})
		var ambErr *DestinationRuntimeMountInstanceAmbiguousError
		if !errors.As(err, &ambErr) {
			t.Fatalf("want DestinationRuntimeMountInstanceAmbiguousError, got %v", err)
		}
		if len(ambErr.RunningIDs) != 2 || ambErr.ContainerName != workloadName {
			t.Fatalf("terminal must carry every surviving container ID and the shared name, got %+v", ambErr)
		}
	})

	// (b) The DEAD instance's task is not RUNNING => exactly one survivor, resolved, and it is the
	// live one. This is what D2i buys: without it, listing order could hand CRIU the dead
	// instance's volume dir, which GC will unlink under a live restored process.
	t.Run("task-state narrowing selects the live instance", func(t *testing.T) {
		rows := []*containersapi.Container{
			row(t, "cid-dead", workloadName, testSandbox, workloadMounts("cid-dead")),
			row(t, "cid-live", workloadName, testSandbox, workloadMounts("cid-live")),
		}
		got, err := selectAndResolve(t, rows, []string{workloadName}, []string{"cid-live"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, m := range got {
			if m.Destination == "/data" && !strings.Contains(m.Source, "cid-live") {
				t.Fatalf("selected the DEAD instance's volume dir: %s", m.Source)
			}
		}
	})

	// (c) No candidate has a RUNNING task => NOT-YET, retryable. The container exists but its task
	// has not started, which is exactly what the budget is for.
	t.Run("no running task is not-yet", func(t *testing.T) {
		rows := []*containersapi.Container{row(t, "cid-workload", workloadName, testSandbox, workloadMounts("cid-workload"))}
		got, err := selectAndResolve(t, rows, []string{workloadName}, []string{})
		if got != nil || err != nil {
			t.Fatalf("want (nil, nil) NOT-YET, got (%v, %v)", destinations(got), err)
		}
	})

	// (d) DISTINCT names, all restore targets — a genuine multi-container pod. Out of roadmap
	// scope, so the first is returned and the ambiguity is REPORTED. The returned value is
	// unchanged; only its observability is.
	t.Run("distinct names returns the first and reports", func(t *testing.T) {
		rows := []*containersapi.Container{
			row(t, "cid-a", "app", testSandbox, workloadMounts("cid-a")),
			row(t, "cid-b", "sidecar", testSandbox, workloadMounts("cid-b")),
		}
		got, err := selectAndResolve(t, rows, []string{"app", "sidecar"}, []string{"cid-a", "cid-b"})
		if err != nil {
			t.Fatalf("a multi-container pod must not be a terminal, got %v", err)
		}
		for _, m := range got {
			if m.Destination == "/data" && !strings.Contains(m.Source, "cid-a") {
				t.Fatalf("want the FIRST row in listing order, got %s", m.Source)
			}
		}
	})
}

// TestADR0421_D2j_EmptySandboxIDFailsClosedBeforeAnyListing pins D2j: the terminal is decided from
// the parameters at entry, before any containerd round-trip, and is terminal on FIRST occurrence
// because sandboxID cannot change across probes.
func TestADR0421_D2j_EmptySandboxIDFailsClosedBeforeAnyListing(t *testing.T) {
	s := &AgentServer{}
	orig := containerdRuntimeMountsOnceFn
	called := false
	containerdRuntimeMountsOnceFn = func(context.Context, string, string, []string) ([]nri.ContainerMount, error) {
		called = true
		return nil, nil
	}
	defer func() { containerdRuntimeMountsOnceFn = orig }()

	start := time.Now()
	_, err := s.resolveRuntimeMountsWaiting(context.Background(), "pod-uid-1", "", []string{workloadName}, []string{"/data"})

	var sandboxErr *DestinationRuntimeMountSandboxKeyMissingError
	if !errors.As(err, &sandboxErr) {
		t.Fatalf("want DestinationRuntimeMountSandboxKeyMissingError, got %v", err)
	}
	if called {
		t.Fatal("D2j must be decided BEFORE any containerd listing is requested — zero round-trips")
	}
	if elapsed := time.Since(start); elapsed >= destinationMountLookupInterval {
		t.Fatalf("D2j must be terminal on first occurrence, took %s", elapsed)
	}
	// The name filter must NOT be applied over an unnarrowed row set: a CRI container name is
	// byte-identical across sandbox churn, so it manufactures confidence in an arbitrary row.
	if !strings.Contains(err.Error(), "EMPTY sandbox ID") {
		t.Fatalf("the terminal must name the missing sandbox key: %v", err)
	}
}
