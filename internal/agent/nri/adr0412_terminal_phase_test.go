/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package nri

// adr0412_terminal_phase_test.go pins ADR-0412: the NRI restore anti-spoof gate must not treat a
// MONOTONIC terminal phase (Complete/Failed/RollingBack/DryRunComplete) as a TRANSIENT
// "phase is ..." blip. It covers:
//
//	D1 — the ADR-0197 Rule D non-restore-target pass-through runs BEFORE the anti-spoof/phase gate,
//	     so a non-target init container never wedges on a terminal-phase check it was designed to
//	     skip.
//	D2 — the gate classifies a matched migration into four+ outcomes: proceed (accept-set),
//	     terminal-own → clean cold-start, terminal-not-own / Failed / RollingBack → fail-closed
//	     reject, wrong-node → fail-closed reject, and genuinely mid-flight → transient retry.
//	condition #1 — the StartContainer decision is THREADED to PostStartContainer (not re-derived),
//	     so a phase transition between the two hooks cannot make them disagree.
//	condition #2 — the PostStartContainer terminal-own skip path (both the threaded and the
//	     fallback-re-derive legs) has explicit failure-mode coverage.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
	"github.com/podmotion-io/podmotion/internal/metrics"
)

const (
	adr0412Node = "dest-node-1"
	adr0412NS   = "default"
	adr0412Ref  = "adr0412-mig"
	adr0412Pod  = "app-src-m-abc123" // the replacement (destination) pod, == event.Pod
)

func adr0412Scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pmv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return scheme
}

// adr0412Client builds a fake client holding a single PodMigration with the given phase, node, and
// replacementPodName.
func adr0412Client(t *testing.T, phase pmv1.MigrationPhase, destNode, replacementPod string) client.Client {
	t.Helper()
	pm := &pmv1.PodMigration{
		ObjectMeta: metav1.ObjectMeta{Name: adr0412Ref, Namespace: adr0412NS},
		Status: pmv1.PodMigrationStatus{
			Phase:               phase,
			DestinationNodeName: destNode,
			ReplacementPodName:  replacementPod,
		},
	}
	return fake.NewClientBuilder().WithScheme(adr0412Scheme(t)).WithObjects(pm).Build()
}

// adr0412RestoreTargetEvent builds a StartContainer/PostStartContainer event for the restore-target
// MAIN container (event.Name is in restore-target-containers).
func adr0412RestoreTargetEvent() ContainerEvent {
	return ContainerEvent{
		ID:        "ctr-main-1",
		Name:      "app",
		Namespace: adr0412NS,
		Pod:       adr0412Pod,
		Annotations: map[string]string{
			"podmotion.io/checkpoint-ref":            adr0412Ref,
			"podmotion.io/restore-target-containers": "app",
		},
	}
}

// ---------------------------------------------------------------------------
// D2 classification — direct verifyPodMigration coverage (fast, no retry loop).
// ---------------------------------------------------------------------------

func TestADR0412_VerifyPodMigration_Classification(t *testing.T) {
	cases := []struct {
		name           string
		phase          pmv1.MigrationPhase
		destNode       string
		replacementPod string
		// expectations
		wantNil          bool
		wantOwnColdStart bool
		wantTerminalNot  bool
		wantNodeMismatch bool
		wantPhaseIs      bool
	}{
		{name: "Restoring/own → proceed", phase: pmv1.MigrationPhaseRestoring, destNode: adr0412Node, replacementPod: adr0412Pod, wantNil: true},
		{name: "RestoreSocketReattach → proceed", phase: pmv1.MigrationPhaseRestoreSocketReattach, destNode: adr0412Node, wantNil: true},
		{name: "DisengageHold → proceed", phase: pmv1.MigrationPhaseDisengageHold, destNode: adr0412Node, wantNil: true},
		{name: "Complete+own → cold-start sentinel", phase: pmv1.MigrationPhaseComplete, destNode: adr0412Node, replacementPod: adr0412Pod, wantOwnColdStart: true},
		{name: "Complete+not-own → terminal reject", phase: pmv1.MigrationPhaseComplete, destNode: adr0412Node, replacementPod: "some-other-pod", wantTerminalNot: true},
		{name: "Complete+empty-replacement → terminal reject", phase: pmv1.MigrationPhaseComplete, destNode: adr0412Node, replacementPod: "", wantTerminalNot: true},
		{name: "Failed+own → terminal reject (split-brain guard)", phase: pmv1.MigrationPhaseFailed, destNode: adr0412Node, replacementPod: adr0412Pod, wantTerminalNot: true},
		{name: "RollingBack+own → terminal reject", phase: pmv1.MigrationPhaseRollingBack, destNode: adr0412Node, replacementPod: adr0412Pod, wantTerminalNot: true},
		{name: "DryRunComplete+own → terminal reject", phase: pmv1.MigrationPhaseDryRunComplete, destNode: adr0412Node, replacementPod: adr0412Pod, wantTerminalNot: true},
		{name: "OverlayHandoff → transient phase-is", phase: pmv1.MigrationPhaseOverlayHandoff, destNode: adr0412Node, wantPhaseIs: true},
		{name: "Pending → transient phase-is", phase: pmv1.MigrationPhasePending, destNode: adr0412Node, wantPhaseIs: true},
		{name: "wrong-node (Restoring) → node mismatch (checked first)", phase: pmv1.MigrationPhaseRestoring, destNode: "other-node", replacementPod: adr0412Pod, wantNodeMismatch: true},
		{name: "wrong-node (Complete+own) → node mismatch (checked first)", phase: pmv1.MigrationPhaseComplete, destNode: "other-node", replacementPod: adr0412Pod, wantNodeMismatch: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(nil, nil).WithK8sVerification(adr0412Client(t, tc.phase, tc.destNode, tc.replacementPod), adr0412Node)
			err := p.verifyPodMigration(context.Background(), adr0412NS, adr0412Pod, adr0412Ref)

			switch {
			case tc.wantNil:
				if err != nil {
					t.Fatalf("expected nil (proceed), got %v", err)
				}
			case tc.wantOwnColdStart:
				if err != errRestoreNotApplicableTerminalOwn {
					t.Fatalf("expected errRestoreNotApplicableTerminalOwn, got %v", err)
				}
				if isPhaseTransientErr(err) {
					t.Fatal("terminal-own sentinel must NOT be transient")
				}
			case tc.wantTerminalNot:
				if err == nil {
					t.Fatal("expected fail-closed terminal reject, got nil")
				}
				if !isErrTerminalNotOwn(err) {
					t.Fatalf("expected errTerminalNotOwn, got %v", err)
				}
				if strings.Contains(err.Error(), "phase is") {
					t.Fatalf("terminal reject must NOT contain \"phase is\" (would be retried forever): %v", err)
				}
				if isPhaseTransientErr(err) {
					t.Fatal("terminal reject must NOT be transient")
				}
			case tc.wantNodeMismatch:
				if err == nil {
					t.Fatal("expected fail-closed node mismatch, got nil")
				}
				if !isErrNodeMismatch(err) {
					t.Fatalf("expected errNodeMismatch, got %v", err)
				}
				if strings.Contains(err.Error(), "phase is") {
					t.Fatalf("node mismatch must NOT contain \"phase is\": %v", err)
				}
			case tc.wantPhaseIs:
				if err == nil || !strings.Contains(err.Error(), "phase is") {
					t.Fatalf("expected transient \"phase is\" error, got %v", err)
				}
				if !isPhaseTransientErr(err) {
					t.Fatal("mid-flight phase must be transient")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// D1 — Rule D non-target pass-through runs BEFORE the gate.
// ---------------------------------------------------------------------------

// TestADR0412_InitContainerNonTargetPassesThroughRegardlessOfTerminalPhase proves the D1 reorder:
// the init container (NOT in restore-target-containers) short-circuits at Rule D and returns nil
// even though the owning migration is Complete-but-not-own — a state that WOULD fail-closed-block
// if the gate ran first. If the gate still ran ahead of Rule D, this would return the terminal
// reject error instead of nil.
func TestADR0412_InitContainerNonTargetPassesThroughRegardlessOfTerminalPhase(t *testing.T) {
	// Complete + replacementPod != the init container's pod → terminal-not-own → the gate, if
	// reached, would return a blocking error.
	p := New(nil, nil).WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseComplete, adr0412Node, "unrelated-pod"), adr0412Node)

	initEvent := ContainerEvent{
		ID:        "ctr-init-1",
		Name:      "podmotion-inject-holder", // NOT in restore-target-containers
		Namespace: adr0412NS,
		Pod:       adr0412Pod,
		Annotations: map[string]string{
			"podmotion.io/checkpoint-ref":            adr0412Ref,
			"podmotion.io/restore-target-containers": "app", // only the main container
		},
	}

	if err := p.HandleStartContainer(context.Background(), initEvent); err != nil {
		t.Fatalf("init (non-target) container must clean-pass-through via Rule D BEFORE the gate; got blocking error (D1 order regression): %v", err)
	}
	// And no decision should be recorded for a non-target container (the gate never ran).
	if _, found := p.takeStartDecision(initEvent.ID); found {
		t.Fatal("no start decision should be recorded for a non-restore-target container")
	}
}

// ---------------------------------------------------------------------------
// D2 (a) — terminal-own restore-target cold-starts; no restore triggered.
// ---------------------------------------------------------------------------

func TestADR0412_RestoreTargetOwnCompleteColdStarts(t *testing.T) {
	before := testutil.ToFloat64(metrics.NRIRestoreGateOutcomeTotal.WithLabelValues("terminal_own_coldstart"))

	restoreCh := make(chan struct{}, 1)
	p := New(nil, func(context.Context, ContainerEvent, string) error {
		restoreCh <- struct{}{}
		return nil
	}).WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseComplete, adr0412Node, adr0412Pod), adr0412Node)

	event := adr0412RestoreTargetEvent()

	// StartContainer: own-complete → clean cold-start (nil), decision recorded.
	if err := p.HandleStartContainer(context.Background(), event); err != nil {
		t.Fatalf("terminal-own restore-target must cold-start (nil); got %v", err)
	}
	if after := testutil.ToFloat64(metrics.NRIRestoreGateOutcomeTotal.WithLabelValues("terminal_own_coldstart")); after != before+1 {
		t.Fatalf("terminal_own_coldstart counter: want %v, got %v", before+1, after)
	}

	// PostStartContainer: consumes the threaded terminal-own decision → skip barrier + restore.
	if err := p.HandlePostStartContainer(context.Background(), event); err != nil {
		t.Fatalf("PostStartContainer must return nil on terminal-own; got %v", err)
	}
	select {
	case <-restoreCh:
		t.Fatal("OnStartContainer (CRIU restore) was invoked for a terminal-own cold-start — stale checkpoint memory would be re-restored")
	case <-time.After(300 * time.Millisecond):
		// good — no restore fired
	}
}

// ---------------------------------------------------------------------------
// D2 (b) — terminal-not-own and Failed still fail-closed reject.
// ---------------------------------------------------------------------------

func TestADR0412_TerminalNotOwnFailClosed(t *testing.T) {
	restoreCh := make(chan struct{}, 1)
	p := New(nil, func(context.Context, ContainerEvent, string) error {
		restoreCh <- struct{}{}
		return nil
	}).WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseComplete, adr0412Node, "an-unrelated-completed-pod"), adr0412Node)

	err := p.HandleStartContainer(context.Background(), adr0412RestoreTargetEvent())
	if err == nil {
		t.Fatal("terminal-not-own (stale/forged ref → unrelated Complete migration) must be fail-closed-rejected; got nil")
	}
	if strings.Contains(err.Error(), "phase is") {
		t.Fatalf("terminal reject must be PERMANENT (no \"phase is\", else retried forever): %v", err)
	}
	if isPhaseTransientErr(err) {
		t.Fatalf("terminal reject must not be transient: %v", err)
	}
	select {
	case <-restoreCh:
		t.Fatal("OnStartContainer invoked on a fail-closed terminal-not-own reject")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestADR0412_FailedPhaseFailClosedEvenIfOwn(t *testing.T) {
	// Failed + ReplacementPodName == this pod: even the pod's OWN Failed/aborted migration must NOT
	// cold-start — that risks a second live instance alongside the ADR-0157-thawed source.
	p := New(nil, nil).WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseFailed, adr0412Node, adr0412Pod), adr0412Node)

	err := p.HandleStartContainer(context.Background(), adr0412RestoreTargetEvent())
	if err == nil {
		t.Fatal("Failed-phase (even own) must be fail-closed; got nil")
	}
	if strings.Contains(err.Error(), "phase is") {
		t.Fatalf("Failed reject must be permanent (no \"phase is\"): %v", err)
	}
}

// ---------------------------------------------------------------------------
// D2 (c) — node mismatch still fail-closed rejects.
// ---------------------------------------------------------------------------

func TestADR0412_NodeMismatchFailClosed(t *testing.T) {
	p := New(nil, nil).WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseRestoring, "some-other-node", adr0412Pod), adr0412Node)

	err := p.HandleStartContainer(context.Background(), adr0412RestoreTargetEvent())
	if err == nil {
		t.Fatal("wrong-node ref must be fail-closed; got nil")
	}
	if strings.Contains(err.Error(), "phase is") {
		t.Fatalf("node mismatch must fail FAST (no \"phase is\" spin): %v", err)
	}
	if !isErrNodeMismatch(err) {
		t.Fatalf("expected errNodeMismatch wrapped, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// D2 (e) — genuinely mid-flight phase still retries/waits (transient), then blocks.
// ---------------------------------------------------------------------------

func TestADR0412_MidFlightTransientStillWaits(t *testing.T) {
	// OverlayHandoff is a legitimate pre-FDB in-flight phase — still transient, still retried until
	// the budget expires, then blocked with a "phase is" error (unchanged pre-ADR behavior).
	p := New(nil, nil).WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseOverlayHandoff, adr0412Node, adr0412Pod), adr0412Node)

	start := time.Now()
	err := p.HandleStartContainer(context.Background(), adr0412RestoreTargetEvent())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("mid-flight OverlayHandoff must block on budget expiry; got nil")
	}
	if !strings.Contains(err.Error(), "phase is") {
		t.Fatalf("mid-flight reject must be the transient \"phase is\" error (so it retries): %v", err)
	}
	// The loop must actually have waited (retried) at least one poll interval before giving up —
	// proving OverlayHandoff is still treated as transient, not as an immediate permanent reject.
	if elapsed < antiSpoofVerifyPollInterval {
		t.Fatalf("mid-flight phase returned in %s (< one poll interval %s) — it was NOT retried as transient", elapsed, antiSpoofVerifyPollInterval)
	}
}

// ---------------------------------------------------------------------------
// condition #1 — the StartContainer decision is THREADED to PostStartContainer.
// ---------------------------------------------------------------------------

// TestADR0412_ThreadedDecisionSurvivesPhaseTransition exercises a phase transition occurring
// BETWEEN the two hook calls for a genuine restore-target container. StartContainer sees an
// accept-set phase (Restoring) and records "proceed". The migration then advances to Complete-own
// before PostStartContainer fires. PostStartContainer MUST act on the THREADED "proceed" decision
// (run the restore it already authorized) rather than RE-DERIVING from the now-Complete CR (which
// would wrongly skip). This is the New Engineer / condition #1 guarantee: the two hooks consume
// ONE computed outcome, so a between-hooks transition cannot make them disagree.
func TestADR0412_ThreadedDecisionSurvivesPhaseTransition(t *testing.T) {
	origSentinel := verifyCheckpointProvenanceSentinel
	verifyCheckpointProvenanceSentinel = func(string) error { return nil }
	defer func() { verifyCheckpointProvenanceSentinel = origSentinel }()

	restoreCh := make(chan struct{}, 1)
	p := New(nil, func(context.Context, ContainerEvent, string) error {
		restoreCh <- struct{}{}
		return nil
	})

	// StartContainer against a Restoring (accept-set) CR → records restoreDecisionProceed.
	p.WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseRestoring, adr0412Node, adr0412Pod), adr0412Node)
	if err := p.HandleStartContainer(context.Background(), adr0412RestoreTargetEvent()); err != nil {
		t.Fatalf("StartContainer on Restoring must return nil (deferred restore); got %v", err)
	}
	if d, found := peekDecision(p, "ctr-main-1"); !found || d != restoreDecisionProceed {
		t.Fatalf("StartContainer must record restoreDecisionProceed; found=%v d=%v", found, d)
	}

	// Simulate the between-hooks phase transition: the CR now reads Complete-own. If
	// PostStartContainer RE-DERIVED, it would classify terminal-own and WRONGLY skip the restore.
	p.WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseComplete, adr0412Node, adr0412Pod), adr0412Node)

	event := adr0412RestoreTargetEvent()
	// No "original-command-overridden" annotation → the holder barrier fast-path passes, so the
	// async restore reaches OnStartContainer without a real holder.
	if err := p.HandlePostStartContainer(context.Background(), event); err != nil {
		t.Fatalf("PostStartContainer returned error; got %v", err)
	}

	select {
	case <-restoreCh:
		// good — the threaded "proceed" decision won; the restore ran as StartContainer authorized.
	case <-time.After(5 * time.Second):
		t.Fatal("OnStartContainer did not run — PostStartContainer re-derived from the now-Complete CR and skipped the restore instead of consuming the threaded proceed decision (condition #1 regression)")
	}
}

// ---------------------------------------------------------------------------
// condition #2 — PostStartContainer terminal-own skip: failure-mode coverage.
// ---------------------------------------------------------------------------

// TestADR0412_PostStartThreadedTerminalOwnSkips covers the threaded leg: a recorded terminal-own
// decision makes PostStartContainer skip the barrier + restore.
func TestADR0412_PostStartThreadedTerminalOwnSkips(t *testing.T) {
	origSentinel := verifyCheckpointProvenanceSentinel
	verifyCheckpointProvenanceSentinel = func(string) error { return nil }
	defer func() { verifyCheckpointProvenanceSentinel = origSentinel }()

	restoreCh := make(chan struct{}, 1)
	p := New(nil, func(context.Context, ContainerEvent, string) error {
		restoreCh <- struct{}{}
		return nil
	}).WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseComplete, adr0412Node, adr0412Pod), adr0412Node)

	// Record the terminal-own decision via a real StartContainer call.
	if err := p.HandleStartContainer(context.Background(), adr0412RestoreTargetEvent()); err != nil {
		t.Fatalf("StartContainer terminal-own must be nil; got %v", err)
	}
	if err := p.HandlePostStartContainer(context.Background(), adr0412RestoreTargetEvent()); err != nil {
		t.Fatalf("PostStartContainer must be nil on terminal-own; got %v", err)
	}
	select {
	case <-restoreCh:
		t.Fatal("terminal-own PostStartContainer ran the CRIU restore (must skip)")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestADR0412_PostStartMissingDecisionReDerivesFailClosed covers the FALLBACK leg (condition #2
// failure mode): PostStartContainer fires WITHOUT a preceding threaded decision (e.g. the agent
// restarted between the two hooks). It must re-derive fail-closed — when the CR is terminal it must
// NOT run the restore, even though no decision was threaded.
func TestADR0412_PostStartMissingDecisionReDerivesFailClosed(t *testing.T) {
	origSentinel := verifyCheckpointProvenanceSentinel
	verifyCheckpointProvenanceSentinel = func(string) error { return nil }
	defer func() { verifyCheckpointProvenanceSentinel = origSentinel }()

	restoreCh := make(chan struct{}, 1)
	// Terminal-not-own CR — a stale/forged terminal ref. No StartContainer call ⇒ no threaded
	// decision ⇒ PostStartContainer must re-derive and skip (fail-closed, no fail-open restore).
	p := New(nil, func(context.Context, ContainerEvent, string) error {
		restoreCh <- struct{}{}
		return nil
	}).WithK8sVerification(adr0412Client(t, pmv1.MigrationPhaseComplete, adr0412Node, "unrelated-pod"), adr0412Node)

	if err := p.HandlePostStartContainer(context.Background(), adr0412RestoreTargetEvent()); err != nil {
		t.Fatalf("PostStartContainer must return nil; got %v", err)
	}
	select {
	case <-restoreCh:
		t.Fatal("PostStartContainer with no threaded decision + terminal CR ran the restore — fail-OPEN (must fail-closed skip)")
	case <-time.After(300 * time.Millisecond):
	}
}

// ---------------------------------------------------------------------------
// Invariant anchors — accept-set unchanged, terminal not transient.
// ---------------------------------------------------------------------------

func TestADR0412_AcceptSetUnchanged(t *testing.T) {
	accept := []pmv1.MigrationPhase{
		pmv1.MigrationPhaseRestoring, pmv1.MigrationPhaseRestoreSocketReattach, pmv1.MigrationPhaseDisengageHold,
	}
	for _, ph := range accept {
		if !isRestoreAcceptPhase(ph) {
			t.Errorf("phase %q must be in the accept-set", ph)
		}
	}
	reject := []pmv1.MigrationPhase{
		pmv1.MigrationPhaseOverlayHandoff, pmv1.MigrationPhaseComplete, pmv1.MigrationPhaseFailed,
		pmv1.MigrationPhaseRollingBack, pmv1.MigrationPhaseDryRunComplete, pmv1.MigrationPhasePending,
		pmv1.MigrationPhaseFinalFreezeStateCapture,
	}
	for _, ph := range reject {
		if isRestoreAcceptPhase(ph) {
			t.Errorf("phase %q must NOT be in the accept-set (accept-set must not be widened)", ph)
		}
	}
}

func TestADR0412_TerminalNotClassifiedTransient(t *testing.T) {
	if isPhaseTransientErr(errRestoreNotApplicableTerminalOwn) {
		t.Error("terminal-own sentinel must NOT be transient")
	}
	if isPhaseTransientErr(errTerminalNotOwn) {
		t.Error("terminal-not-own must NOT be transient")
	}
	if isPhaseTransientErr(errNodeMismatch) {
		t.Error("node-mismatch must NOT be transient")
	}
	// A genuine mid-flight phase error MUST remain transient (unchanged).
	if !isPhaseTransientErr(verifyPhaseInAcceptSet("OverlayHandoff")) {
		t.Error("OverlayHandoff must remain transient")
	}
}

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

func isErrTerminalNotOwn(err error) bool { return errors.Is(err, errTerminalNotOwn) }
func isErrNodeMismatch(err error) bool   { return errors.Is(err, errNodeMismatch) }

// peekDecision reads (without removing) a recorded decision for id.
func peekDecision(p *Plugin, id string) (restoreDecision, bool) {
	p.startDecisionsMu.Lock()
	defer p.startDecisionsMu.Unlock()
	e, ok := p.startDecisions[id]
	return e.decision, ok
}
