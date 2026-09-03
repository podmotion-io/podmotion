/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package server

// adr0419_destination_mounts.go — ADR-0419: destination mount truth from the runtime.
//
// The destination host path for a Class DESTINATION-REBIND mount is an AUTHORITATIVE READ,
// not an inference. Two sources, one shape:
//
//   - NRI restore path: the mount list arrives ON the ContainerEvent itself
//     (nri.ContainerEvent.Mounts, D1) — zero query, zero poll, zero retry.
//   - gRPC restore paths: one TYPED containerd round-trip (D5) — never a `ctr` scrape.
//
// Both feed the SAME lookup (D3): find the runtime entry whose Destination equals the
// in-container path the checkpoint demands (D4) and take its Source. containerd could not
// have created the container without resolving those binds, so each Source's existence is a
// precondition of the event's delivery — there is no edge left to wait on and no probe to make.
//
// This replaces ADR-0417's target RESOLUTION mechanism only. Its classification thesis (the
// fstype-keyed recreatability partition in patch_checkpoint_script.go, reattachTierDestinationRebind,
// the reattachContainerPaths exclusion, --ext-mount-map emission) is untouched.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	taskapi "github.com/containerd/containerd/api/types/task"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/podmotion-io/podmotion/internal/agent/netnsbroker"
	"github.com/podmotion-io/podmotion/internal/agent/nri"
)

// ---------------------------------------------------------------------------------------------
// D5.2 — the successor budget and cadence for the gRPC typed-lookup path.
// ---------------------------------------------------------------------------------------------

// destinationMountLookupBudget bounds the gRPC-path typed runtime-mount lookup. It REPLACES the
// retired destinationRebindWaitBudget (ADR-0417) and carries that constant's invariant forward
// verbatim. The NRI path needs no successor at all: it has no wait.
//
// GROUNDED IN A REAL MEASUREMENT, not copied from a neighbouring constant. Measured on the
// standing KVM cluster with a passive typed-client probe against each node's own live containerd
// (RKE2 v1.35.6+rke2r1, containerd 2.2.5-k3s2) over its real control socket
// /run/k3s/containerd/containerd.sock. The probe performed the FULL D5 shape — ContainersClient
// List(filtered) + Get + OCI-spec decode — 12 iterations per node, first two discarded as
// connection warm-up, 10 samples retained each (ms):
//
//	pm-w1: 1.60 1.61 1.64 1.76 1.98 1.99 2.15 2.16 3.21 3.73   (median 1.99, max 3.73)
//	pm-w2: 1.32 1.67 1.68 1.72 1.74 1.86 1.93 2.53 2.71 5.12   (median 1.86, max 5.12)
//
// A healthy typed round-trip is therefore ~2ms and the observed worst sample is ~5ms — and the
// shipped code is strictly CHEAPER than what was measured (it issues the List only; the response
// already carries each container's OCI spec, so the Get is not performed). The entire 10s is
// consequently blip headroom, none of it healthy-path cost: it is ~2000x the measured healthy
// round-trip and ~2000x the worst observed sample, sized to ride out the containerd
// control-plane stall FM5 observed rather than to scale off the healthy latency.
//
// (Recorded honestly: ADR-0419 D5.2 estimated 10s to be "~20x a healthy typed round-trip". The
// measurement says the real ratio is three orders of magnitude larger, because a typed round-trip
// is sub-3ms rather than the ~500ms the CLI-scrape chain it replaces cost. That STRENGTHENS the
// choice of 10s rather than undermining it — but the ADR's stated ratio was an estimate, and this
// block records the measurement, not the estimate. §5.8: a budget without a measurement is
// forbidden, and so is one whose stated grounding does not match what was measured.)
//
// INVARIANT (asserted mechanically at TestADR0419_LookupBudgetIsStrictlyUnderBothSiblings):
// destinationMountLookupBudget is STRICTLY UNDER both sibling budgets on this same restore path
// — the 60s replacement-sandbox wait and the 85s reattach-mount wait — so this lookup can NEVER
// be the component that consumes D_restore. That property is exactly what the retired constant's
// own doc block guaranteed, and it is why the pair is REPLACED rather than merely removed:
// mandating a re-probe while deleting its bound would silently make "the remaining budget" mean
// all of D_restore (the gRPC sites pass the raw handler ctx, documented in-tree as "the real
// budget source on this path"), handing the mount probe precisely the ability the deleted bound
// guaranteed it could never have. It is also an availability primitive: without it, anyone who
// can push a node into containerd Unavailable pins a privileged agent goroutine and an in-flight
// migration for the whole restore deadline.
var destinationMountLookupBudget = 10 * time.Second

// destinationMountLookupInterval is the re-probe cadence inside destinationMountLookupBudget
// (var for tests). 1s matches the kubelet-edge cadence of replacementSandboxPollInterval and
// resolveReattachMountsWaiting rather than the retired 250ms: there is no sub-second file-creation
// edge to catch here. The transient being ridden out is a containerd control-plane blip, and a
// 250ms cadence against a stalled control socket only multiplies load on the thing that is already
// struggling — the exact substrate-degradation dynamic (root cause C) this ADR removes.
var destinationMountLookupInterval = 1 * time.Second

// ---------------------------------------------------------------------------------------------
// Terminal error classes introduced by this ADR. All three are named, fail-closed, and carry the
// specific fact that failed — never a generic deadline.
// ---------------------------------------------------------------------------------------------

// DestinationRuntimeMountAbsentError (D3) is the hard-stop for a mount THIS CHECKPOINT demands
// (D4) that the container runtime did not give this container.
//
// This is a genuinely different fact from anything ADR-0417 could report. Its predecessor
// (DestinationRebindTargetNotStagedError) said "we did not observe a file within a budget" — an
// unobserved edge. This says "the runtime's own authoritative mount list, which containerd could
// not have created this container without resolving, contains no entry for this path". A definite
// fact from an authoritative source, available immediately, with no budget to spend.
type DestinationRuntimeMountAbsentError struct {
	ContainerPath string
	SandboxID     string
	// KnownDestinations is the set of in-container paths the runtime DID supply, so the
	// transcript shows what was actually on offer rather than only what was missing.
	KnownDestinations []string
	// Source names where the runtime mount list came from ("NRI ContainerEvent" or
	// "containerd containers service"), so a reader can tell which of the two paths failed.
	Source string
}

func (e *DestinationRuntimeMountAbsentError) Error() string {
	return fmt.Sprintf("destination rebind: the runtime did not give this container a mount at %s (sandbox %s, mount list from %s; runtime supplied %d destinations: %s) — refusing to rewrite a checkpointed mount's recorded source to a path this container does not actually have (ADR-0419 D3)",
		e.ContainerPath, e.SandboxID, e.Source, len(e.KnownDestinations), strings.Join(e.KnownDestinations, ", "))
}

// DestinationRuntimeMountLookupTimeoutError (D5.3) is the gRPC path's NEVER terminal: a NOT-YET
// that never converged inside destinationMountLookupBudget.
//
// It exists because deleting the old classifier's only NEVER type without a successor would have
// left a never-resolving lookup with NO terminal at all — it would burn D_restore and surface as a
// bare RPC timeout, re-creating exactly the misattribution ADR-0418 just fixed. It names the
// unresolved in-container path and the last gRPC status seen.
type DestinationRuntimeMountLookupTimeoutError struct {
	ContainerPath string
	PodUID        string
	SandboxID     string
	Attempts      int
	Waited        time.Duration
	LastStatus    string
}

func (e *DestinationRuntimeMountLookupTimeoutError) Error() string {
	return fmt.Sprintf("destination rebind: the container runtime never returned a mount list for pod uid %s / sandbox %s within %s (%d typed lookups, last gRPC status %s) — %s could not be resolved (ADR-0419 D5.3)",
		e.PodUID, e.SandboxID, e.Waited.Round(time.Millisecond), e.Attempts, e.LastStatus, e.ContainerPath)
}

// AmbiguousPodSandboxError (D8) is returned when MORE THAN ONE RUNNING kind==sandbox row exists
// for a single pod UID. This is the genuinely ambiguous case and is correctly terminal — picking
// the first row silently, as the pre-ADR-0419 code did, is what made root cause (A) present as a
// timing failure.
//
// It is emphatically NOT the zero-match case: zero matches remains the retryable
// errNoSandboxForPodUID "not yet" edge the pod-netns-join gate bounded-waits on (D8, row 10).
type AmbiguousPodSandboxError struct {
	PodUID     string
	SandboxIDs []string
}

func (e *AmbiguousPodSandboxError) Error() string {
	return fmt.Sprintf("pod uid %s has %d RUNNING pod sandboxes (%s) — refusing to pick one; a restore joined to the wrong sandbox lands the workload in a namespace that is not its pod's (ADR-0419 D8)",
		e.PodUID, len(e.SandboxIDs), strings.Join(e.SandboxIDs, ", "))
}

// ---------------------------------------------------------------------------------------------
// D4 — the DEMAND set: which mounts does THIS CHECKPOINT actually classify as DESTINATION-REBIND?
// ---------------------------------------------------------------------------------------------

// destinationRebindDemandSetFn is a test seam over destinationRebindDemandSet.
var destinationRebindDemandSetFn = destinationRebindDemandSet

// destinationRebindDemand is what ONE scan of the checkpoint's own mountpoints images yields.
//
// ADR-0419 returned only Paths. ADR-0420 D1b adds the content-axis classification of the SAME
// scan, because the counter's denominator has to be real: "how many content-bearing recreatable
// externals did this checkpoint have, and how many of them had their content?" is decidable from
// the directory this scan already reads, and answering it here costs no extra subprocess, no extra
// decode, and no new marker line in the patch script's line-oriented output protocol.
type destinationRebindDemand struct {
	// Paths are the in-container mountpoints this checkpoint classifies as Class
	// DESTINATION-REBIND — the set that must resolve a destination target or hard-stop.
	Paths []string `json:"demand"`
	// ContentAbsent is the SUBSET of Paths that are there because of ADR-0420 D1: recreatable,
	// construct-and-fill, and no content image in this checkpoint. Under ADR-0417 these would have
	// been internalized and would have failed silently inside CRIU's tmpfs_restore.
	ContentAbsent []string `json:"content_absent"`
	// InternalizedWithContent counts the content-bearing recreatable externals that DID carry their
	// content and are therefore still internalized — /dev/shm's population. A zero here on a real
	// migration means the dump-side capture stopped producing content images.
	InternalizedWithContent int `json:"internalized_with_content"`
}

// destinationRebindDemandScanPy mirrors patch_checkpoint_script.go's Class DESTINATION-REBIND
// predicate EXACTLY, and is the reason a workload whose checkpoint has no /etc/hostname mount no
// longer hard-stops on a demand it never made.
//
// An entry is DEMANDED iff it is EXTERNAL (truthy ext_key), has a mnt_id and a mountpoint, and the
// patch script would NOT internalize it — i.e. internalization_outcome() returns anything other
// than INTERNALIZE_OK.
//
// ADR-0420 D1c — THIS IS NO LONGER A COPY, AND THAT CHANGE IS THE POINT. Before ADR-0420 this
// scanner carried its own `RECREATABLE_FSTYPES = frozenset((1,2,3,4,5,6,14))` literal and
// `continue`d past every recreatable fstype, because under ADR-0417 those were ALWAYS internalized.
// D1 makes that false: a recreatable, construct-and-fill tmpfs whose content is NOT in the
// checkpoint now routes to DESTINATION-REBIND and therefore DEMANDS a destination target. A scanner
// that kept skipping it would leave that target undemanded and unresolved, and the patch script
// would hard-stop on a mount the destination could have supplied — a FALSE HARD STOP ON EVERY
// MIGRATION. The predicate is therefore prepended from the one shared definition
// (mountContentAxisPy) rather than restated, so the two decoders agree by construction rather than
// by review. TestADR0420_ContentAxisIsTheSingleDefinitionInBothDecoders asserts it mechanically.
//
// It also reports the content-axis classification itself, so ADR-0420 D1b's counter has a REAL
// denominator without a second subprocess, a second decode, or a new marker line: the outcome is a
// pure function of the same directory this scan already reads.
//
// The script's carve-out (a) — storage-tier PVC re-attach — is deliberately NOT modelled here.
// That branch is checked FIRST in the script and its targets are resolved by the storage tier's
// own pass, so the Go side excludes already-resolved mountpoints from the demand set instead (see
// destinationRebindDemandSet's caller). Modelling it here would duplicate a resolution that
// already happened and risk emitting two conflicting targets for one key.
//
// Security (ADR-0121, same contract as readDevShmMountInfo): imagesDir is passed as ARGV and is
// never string-formatted into the script body.
const destinationRebindDemandScanPy = `
import pycriu, glob
ckpt = sys.argv[1]
demand = set()
content_absent = set()
internalized_with_content = 0
for img in sorted(glob.glob(os.path.join(ckpt, 'mountpoints-*.img'))):
    if not img.endswith('.img'):
        continue
    with open(img, 'rb') as f:
        data = pycriu.images.load(f)
    for e in data.get('entries', []):
        ext_key = e.get('ext_key')
        mnt_id = e.get('mnt_id')
        mp = e.get('mountpoint')
        if not ext_key or mnt_id is None or not mp:
            continue
        outcome = internalization_outcome(ckpt, e)
        if outcome == INTERNALIZE_OK:
            # Counted only for the population the content axis actually governs, so the D1b
            # denominator is the set of decisions D1 could have changed — not every kept mount.
            if _is_content_bearing_fstype(e.get('fstype')):
                internalized_with_content += 1
            continue
        if outcome == INTERNALIZE_CONTENT_ABSENT:
            content_absent.add(mp)
        demand.add(mp)
print(json.dumps({
    'demand': sorted(demand),
    'content_absent': sorted(content_absent),
    'internalized_with_content': internalized_with_content,
}))
`

// destinationRebindDemandSet reads the checkpoint's OWN mountpoints image and returns the
// in-container paths it classifies as Class DESTINATION-REBIND.
//
// This is the intersect ADR-0417's hardcoded four-entry table structurally could not perform: the
// demand set becomes the CHECKPOINT's, so a target absent from the checkpoint is never required,
// and a future runtime-injected file bind off a block filesystem is covered with zero new code.
//
// Mechanism is the EXISTING, working one (ADR-0121): vendored pycriu via a python3 subprocess with
// PYTHONPATH=/usr/lib/python3/dist-packages. It deliberately matches readDevShmMountInfo's shape
// rather than inventing a second decoder — including that site's PATH-resolved `python3`, which is
// a RECORDED, separately-tracked exposure this function must not WIDEN and does not (same binary,
// same env, same argv-not-interpolation rule). Pinning it is its own change, out of scope here.
//
// The scratch script is written under the AGENT-OWNED per-migration staging dir rather than
// readDevShmMountInfo's /dev/shm: the restore path cannot assume /dev/shm is writable in the
// agent's own mount namespace, and restoreStagingDir is a tree this process demonstrably owns
// (ensureRestoreTerminationLogFile has already created it by the time this runs).
func destinationRebindDemandSet(ctx context.Context, migrationName, checkpointDir string) (destinationRebindDemand, error) {
	var zero destinationRebindDemand
	if checkpointDir == "" {
		return zero, fmt.Errorf("destination rebind demand set: empty checkpoint dir — refusing to proceed without reading which mounts this checkpoint actually demands (ADR-0419 D4)")
	}
	dir := restoreStagingDir(migrationName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return zero, fmt.Errorf("destination rebind demand set: create staging dir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "pm-demand-scan-*.py")
	if err != nil {
		return zero, fmt.Errorf("destination rebind demand set: create scan script: %w", err)
	}
	scriptPath := f.Name()
	defer os.Remove(scriptPath)
	// ADR-0420 D1c: the shared content axis is prepended, exactly as assemblePatchScript prepends
	// it to the patch script. This is what makes "the two decoders agree" a property of the build
	// rather than a review obligation.
	if _, werr := f.WriteString(mountContentAxisPy + destinationRebindDemandScanPy); werr != nil {
		_ = f.Close()
		return zero, fmt.Errorf("destination rebind demand set: write scan script: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		return zero, fmt.Errorf("destination rebind demand set: close scan script: %w", cerr)
	}

	cmd := exec.CommandContext(ctx, "python3", scriptPath, checkpointDir)
	cmd.Env = append(os.Environ(), "PYTHONPATH=/usr/lib/python3/dist-packages")
	out, err := cmd.Output()
	if err != nil {
		return zero, fmt.Errorf("destination rebind demand set: mountpoints scan failed: %w\n%s", err, out)
	}
	var demand destinationRebindDemand
	if uerr := json.Unmarshal(out, &demand); uerr != nil {
		return zero, fmt.Errorf("destination rebind demand set: parse scan output: %w\n%s", uerr, out)
	}
	return demand, nil
}

// ---------------------------------------------------------------------------------------------
// D5 — the gRPC fallback path's runtime mount list: ONE typed containerd round-trip, never a scrape.
// ---------------------------------------------------------------------------------------------

// containerdNamespace is the CRI containerd namespace every kubelet-created container lives in.
const containerdNamespace = "k8s.io"

// criKindLabel / criPodUIDLabel are the CRI plugin's own container labels. criKindLabel is the
// filter whose ABSENCE is root cause (A): kubelet stamps the pod UID on the pod sandbox AND on
// every workload container, so a pod-UID-only query returns the whole pod and any "first row wins"
// read returns whichever row containerd happens to list first.
const (
	criKindLabel   = "io.cri-containerd.kind"
	criPodUIDLabel = "io.kubernetes.pod.uid"
)

// ociSpecMounts is the subset of the OCI runtime spec this ADR reads. containerd stores a
// container's spec as an Any whose Value is the JSON-encoded OCI spec, so the mount list arrives
// with the OCI spelling (destination/source) — the SAME spelling NRI uses, which is why both
// paths can feed one lookup without a field-name translation layer.
type ociSpecMounts struct {
	Mounts []struct {
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Source      string   `json:"source"`
		Options     []string `json:"options"`
	} `json:"mounts"`
}

// containerdRuntimeMountsOnceFn is a test seam over containerdRuntimeMountsOnce. It is the seam
// the D5.3 status-mapping tests drive with a fake typed client: because the production
// implementation returns a real gRPC status error, a fake can return each code deterministically
// and the four-way classification becomes assertable without a containerd.
var containerdRuntimeMountsOnceFn = containerdRuntimeMountsOnce

// containerdRuntimeMountsOnce performs the single typed containerd round-trip that yields the
// restore-target container's OWN OCI mount list on the gRPC paths.
//
// WHY THE containerd CONTAINERS SERVICE AND NOT CRI ContainerStatus (D5.1, adjudicated on live
// evidence, not on the proto): both candidates were probed on pm-w1 and pm-w2 against the real
// containerd 2.2.5-k3s2. CRI RuntimeService.ContainerStatus(...).Status.Mounts returns only the
// kubelet-SPECIFIED mounts — 3-4 entries, carrying /etc/hosts but carrying NEITHER /etc/hostname
// NOR /etc/resolv.conf, because those two are injected by containerd's CRI plugin into the OCI
// spec and never appear in the CRI container config. D3's lookup would therefore have hard-stopped
// on those two paths for EVERY checkpoint. The containerd containers service returns the FULL OCI
// spec (13-15 mounts on the same containers), carrying all four relevant paths with exactly the
// Source shapes the NRI G0 probe recorded. The CRI option is FALSIFIED for this purpose; this one
// is verified.
//
// HOW THE WORKLOAD-CONTAINER ID IS OBTAINED WITHOUT RE-ENTERING A `ctr` SCRAPE (§P-VERIFY #5):
// the containers service is filtered SERVER-SIDE on
// labels."io.kubernetes.pod.uid"==<replacement pod UID>,labels."io.cri-containerd.kind"==container
// (an AND — both proven to work live), and the result is then narrowed CLIENT-SIDE to the
// container whose Container.Sandbox equals the sandbox ID D2/D2b threaded in. That second step is
// load-bearing, not belt-and-braces: this ADR's own §P-VERIFY #8c settle found 27 pod UIDs across
// the two nodes carrying TWO sandbox rows each, so a pod-UID-only match can select a container
// belonging to a STALE sandbox. Container.Sandbox was verified live to be populated by this
// containerd. (Server-side filtering on sandbox==<id> and on spec.annotations was probed and
// returns 0 rows — containerd's filter grammar does not index either — hence the client-side step.)
//
// ONE ROUND-TRIP: List already returns each Container's Spec, so no follow-up Get is issued.
// §P-VERIFY #10's "exactly one typed round-trip on the healthy path" is satisfied literally.
//
// Returns (nil, nil) — an empty, non-error result — when the sandbox/container genuinely has not
// been created yet. That is a NOT-YET, and the caller re-probes; it is NOT an error, and must
// never be collapsed into one.
func containerdRuntimeMountsOnce(ctx context.Context, podUID, sandboxID string) ([]nri.ContainerMount, error) {
	dialPath, err := containerdDialPath()
	if err != nil {
		return nil, fmt.Errorf("containerd containers client: %w", err)
	}
	conn, err := grpc.NewClient("unix://"+dialPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("containerd containers client for %s (host socket %s): %w", dialPath, containerdSocketPath, err)
	}
	defer func() { _ = conn.Close() }()

	rpcCtx := metadata.AppendToOutgoingContext(ctx, "containerd-namespace", containerdNamespace)
	resp, err := containersapi.NewContainersClient(conn).List(rpcCtx, &containersapi.ListContainersRequest{
		Filters: []string{fmt.Sprintf("labels.%q==%s,labels.%q==container", criPodUIDLabel, podUID, criKindLabel)},
	})
	if err != nil {
		// Returned verbatim so the caller can classify on the TYPED gRPC status. This is the
		// whole point of D5: a status code can say "transient" where a CLI exit code could not,
		// which is what inverts FM5's "one exec deadline kills a live migration" behaviour.
		return nil, err
	}

	for _, c := range resp.GetContainers() {
		if c == nil {
			continue
		}
		// Client-side sandbox narrowing — see the doc comment above for why this is required
		// rather than optional. An empty Container.Sandbox is not matched: an unattributable
		// container is not evidence that it is the right one.
		if sandboxID != "" && c.GetSandbox() != sandboxID {
			continue
		}
		var spec ociSpecMounts
		if uerr := json.Unmarshal(c.GetSpec().GetValue(), &spec); uerr != nil {
			return nil, fmt.Errorf("decode OCI spec for container %s: %w", c.GetID(), uerr)
		}
		out := make([]nri.ContainerMount, 0, len(spec.Mounts))
		for _, m := range spec.Mounts {
			if m.Destination == "" {
				continue
			}
			out = append(out, nri.ContainerMount{
				Destination: m.Destination, Type: m.Type, Source: m.Source, Options: m.Options,
			})
		}
		return out, nil
	}
	// No container for this sandbox yet — a NOT-YET, not a failure.
	return nil, nil
}

// runningPodSandboxesForPodUIDFn is a test seam over runningPodSandboxesForPodUID, so D8's
// tri-state contract can be driven from a fake listing without a live containerd.
var runningPodSandboxesForPodUIDFn = runningPodSandboxesForPodUID

// runningPodSandboxesForPodUID returns the IDs of every RUNNING pod sandbox carrying this pod UID
// (ADR-0419 D8), via one typed containerd containers-service round-trip.
//
// The kind filter root cause (A) was missing is applied SERVER-SIDE
// (labels."io.cri-containerd.kind"==sandbox), so workload containers — which carry the identical
// io.kubernetes.pod.uid label — can never be returned. RUNNING is then established from the
// sandbox container's own live task state.
//
// Ordering is normalized so a caller can never depend on containerd's listing order for meaning;
// with the filters applied, order carries no information and the count is what decides.
func runningPodSandboxesForPodUID(ctx context.Context, podUID string) ([]string, error) {
	dialPath, err := containerdDialPath()
	if err != nil {
		return nil, fmt.Errorf("containerd client: %w", err)
	}
	conn, err := grpc.NewClient("unix://"+dialPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("containerd client for %s (host socket %s): %w", dialPath, containerdSocketPath, err)
	}
	defer func() { _ = conn.Close() }()

	rpcCtx := metadata.AppendToOutgoingContext(ctx, "containerd-namespace", containerdNamespace)
	resp, err := containersapi.NewContainersClient(conn).List(rpcCtx, &containersapi.ListContainersRequest{
		Filters: []string{fmt.Sprintf("labels.%q==%s,labels.%q==sandbox", criPodUIDLabel, podUID, criKindLabel)},
	})
	if err != nil {
		return nil, err
	}
	candidates := make([]string, 0, len(resp.GetContainers()))
	for _, c := range resp.GetContainers() {
		if c != nil && c.GetID() != "" {
			candidates = append(candidates, c.GetID())
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	running, err := runningTaskIDsFn(ctx, conn, candidates)
	if err != nil {
		return nil, err
	}
	sort.Strings(running)
	return running, nil
}

// runningTaskIDsFn is a test seam over runningTaskIDs.
var runningTaskIDsFn = runningTaskIDs

// runningTaskIDs narrows candidate container IDs to those whose containerd TASK is RUNNING.
//
// This is the "and require the match to be RUNNING" half of D8, and it is what makes the answer
// unique rather than merely kind-correct: §P-VERIFY #8c found 27 pod UIDs on the standing cluster
// carrying two kind==sandbox rows apiece, of which exactly one is ever live. Without this filter
// the >1 leg would fire constantly on a healthy cluster and terminalize a gate that works.
//
// A task that is absent (NotFound) is not an error — it is a sandbox container with no live task,
// i.e. precisely the stale row this filter exists to drop.
func runningTaskIDs(ctx context.Context, conn *grpc.ClientConn, candidates []string) ([]string, error) {
	rpcCtx := metadata.AppendToOutgoingContext(ctx, "containerd-namespace", containerdNamespace)
	tc := tasksapi.NewTasksClient(conn)
	running := make([]string, 0, len(candidates))
	for _, id := range candidates {
		resp, err := tc.Get(rpcCtx, &tasksapi.GetRequest{ContainerID: id})
		if err != nil {
			if status.Code(err) == codes.NotFound {
				continue // stale sandbox container with no live task
			}
			return nil, fmt.Errorf("task state for sandbox %s: %w", id, err)
		}
		if resp.GetProcess().GetStatus() == taskapi.Status_RUNNING {
			running = append(running, id)
		}
	}
	return running, nil
}

// runtimeMountLookupClass is the D5.3 four-way classification of one typed lookup attempt.
type runtimeMountLookupClass int

const (
	// runtimeMountLookupResolved: a real mount list came back.
	runtimeMountLookupResolved runtimeMountLookupClass = iota
	// runtimeMountLookupNotYet: re-probe within the budget. Covers BOTH the transient control-plane
	// blip (Unavailable / DeadlineExceeded — the case FM5 currently kills a live migration on, with
	// 29 of 30 seconds unspent) and the genuine "sandbox/container not created yet" (NotFound /
	// empty result).
	runtimeMountLookupNotYet
	// runtimeMountLookupTerminal: fail closed immediately. Anything that is neither a known
	// transient nor a known not-yet.
	runtimeMountLookupTerminal
)

// classifyRuntimeMountLookup maps one lookup outcome onto D5.3's table.
//
// The reclassification is a CONSEQUENCE of holding a real answer, not a retry bolted onto a chain:
// a typed gRPC status distinguishes "the control plane is momentarily unavailable" from "the
// mechanism is structurally broken", which a CLI exit code cannot. ADR-0417 collapsed both into
// terminal-on-first-occurrence, which retried the genuinely unknowable answer ~120 times while
// killing the demonstrably transient one immediately — exactly inverted.
func classifyRuntimeMountLookup(mounts []nri.ContainerMount, err error) runtimeMountLookupClass {
	if err == nil {
		if len(mounts) == 0 {
			return runtimeMountLookupNotYet // empty result: not created yet
		}
		return runtimeMountLookupResolved
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded:
		return runtimeMountLookupNotYet
	case codes.NotFound:
		return runtimeMountLookupNotYet
	}
	return runtimeMountLookupTerminal
}

// resolveRuntimeMountsWaiting runs the typed lookup under D5.2's bound with D5.3's classification.
//
// A NOT-YET that never converges gets a NAMED terminal (DestinationRuntimeMountLookupTimeoutError)
// rather than being allowed to run out D_restore and surface as a bare RPC timeout.
func (s *AgentServer) resolveRuntimeMountsWaiting(ctx context.Context, podUID, sandboxID string, demanded []string) ([]nri.ContainerMount, error) {
	waitCtx, cancel := context.WithTimeout(ctx, destinationMountLookupBudget)
	defer cancel()
	start := time.Now()
	attempts := 0
	lastStatus := "none"
	for {
		attempts++
		mounts, err := containerdRuntimeMountsOnceFn(waitCtx, podUID, sandboxID)
		switch classifyRuntimeMountLookup(mounts, err) {
		case runtimeMountLookupResolved:
			log.Info("ADR-0419 D5: resolved the restore-target container's OCI mount list via one typed containerd round-trip",
				"podUID", podUID, "sandboxID", sandboxID, "mounts", len(mounts),
				"attempts", attempts, "elapsedMs", time.Since(start).Milliseconds())
			return mounts, nil
		case runtimeMountLookupTerminal:
			return nil, fmt.Errorf("destination rebind: typed containerd mount lookup for pod uid %s failed terminally (gRPC status %s): %w", podUID, status.Code(err), err)
		}
		if err != nil {
			lastStatus = status.Code(err).String()
		} else {
			lastStatus = "OK(empty result — sandbox/container not created yet)"
		}
		select {
		case <-waitCtx.Done():
			unresolved := "(all demanded paths)"
			if len(demanded) > 0 {
				unresolved = demanded[0]
			}
			terr := &DestinationRuntimeMountLookupTimeoutError{
				ContainerPath: unresolved, PodUID: podUID, SandboxID: sandboxID,
				Attempts: attempts, Waited: time.Since(start), LastStatus: lastStatus,
			}
			log.Error(terr, "ADR-0419 D5.3: typed runtime-mount lookup never converged within the bounded budget — failing closed with a named terminal",
				"podUID", podUID, "budget", destinationMountLookupBudget.String())
			return nil, terr
		case <-time.After(destinationMountLookupInterval):
		}
	}
}

// ---------------------------------------------------------------------------------------------
// D3 — resolve each demanded target by LOOKUP in the runtime mount list.
// ---------------------------------------------------------------------------------------------

// resolveDestinationRebindTargets is the WHOLE resolution: for each demanded in-container path,
// find the runtime entry whose Destination equals it and take its Source.
//
// No table, no writer taxonomy, no <root>/io.containerd.grpc.v1.cri/sandboxes/<id> reconstruction,
// no existence probe, no bounded wait, no three-way timing classifier.
//
// D3.1 — /dev/termination-log is the ONE documented exception, and D7's value wins. The agent
// itself wrote that file (ensureRestoreTerminationLogFile, two statements earlier), so its own
// os.OpenFile postcondition outranks any other source and the runtime list is NOT consulted for
// it. This is not a stylistic preference: the runtime's Source for /dev/termination-log is
// kubelet's per-container-instance path (live-confirmed shape
// /var/lib/kubelet/pods/<uid>/containers/<name>/<random>), so taking it would silently change the
// emitted --ext-mount-map target for that one path away from ADR-0417's current emission.
// /dev/termination-log absent from the runtime list is therefore NOT a D3 hard stop.
func resolveDestinationRebindTargets(demanded []string, runtimeMounts []nri.ContainerMount, migrationName, sandboxID, source string) ([]reattachMount, error) {
	bySource := make(map[string]string, len(runtimeMounts))
	known := make([]string, 0, len(runtimeMounts))
	for _, m := range runtimeMounts {
		if m.Destination == "" {
			continue
		}
		if _, dup := bySource[normalizeContainerMountPath(m.Destination)]; !dup {
			// `known` reports what the runtime LITERALLY supplied, un-normalized: an operator
			// reading a hard-stop transcript needs the runtime's own spelling, not ours.
			known = append(known, m.Destination)
		}
		bySource[normalizeContainerMountPath(m.Destination)] = m.Source
	}
	sort.Strings(known)

	out := make([]reattachMount, 0, len(demanded))
	for _, containerPath := range demanded {
		if containerPath == restoreTerminationLogContainerPath {
			// D3.1 — D7's agent-staged value wins; the runtime list is not consulted.
			out = append(out, reattachMount{
				ContainerPath: containerPath,
				HostTarget:    restoreTerminationLogPath(migrationName),
				Tier:          reattachTierDestinationRebind,
			})
			continue
		}
		// ADR-0420 D1d: BOTH SIDES of this one comparison are normalized, and nothing else is.
		// ContainerPath below stays the checkpoint's OWN literal mountpoint, because that string is
		// the key the patch script looks its host target up by (reattach_host_targets.get(mp));
		// rewriting it here would silently unresolve the mount one layer down.
		hostTarget, ok := bySource[normalizeContainerMountPath(containerPath)]
		if !ok || hostTarget == "" {
			return nil, &DestinationRuntimeMountAbsentError{
				ContainerPath: containerPath, SandboxID: sandboxID,
				KnownDestinations: known, Source: source,
			}
		}
		out = append(out, reattachMount{
			ContainerPath: containerPath,
			HostTarget:    hostTarget,
			Tier:          reattachTierDestinationRebind,
		})
	}
	return out, nil
}

// restoreTerminationLogContainerPath is the single in-container path D3.1 carves out.
const restoreTerminationLogContainerPath = "/dev/termination-log"

// normalizeContainerMountPath canonicalizes the ONE in-container-path spelling difference that
// makes two strings denote the same mount, so both sides of D3's exact-equality lookup are compared
// in the same domain (ADR-0420 D1d).
//
// WHY THIS EXISTS. ADR-0419's lookup matches a checkpoint-recorded mountpoint against the runtime's
// OCI Destination by exact string equality. That was correct for every path ADR-0419 shipped
// against — /etc/hosts, /etc/hostname, /etc/resolv.conf, /dev/termination-log — because none of
// them traverses a symlinked parent. ADR-0420 D1 routes a NEW member through the same lookup: the
// pod serviceaccount-token tmpfs. The checkpoint records what the kernel's mount table says, which
// the live decode shows as /run/secrets/kubernetes.io/serviceaccount; a pod spec's serviceaccount
// mountPath is /var/run/secrets/kubernetes.io/serviceaccount, and /var/run is a symlink to /run in
// essentially every base image. Two different strings, one mount. Unhandled, D1 would convert a
// SILENT restore failure into a DestinationRuntimeMountAbsent hard stop on every migration — a
// different failure, not a fix.
//
// WHY A PREFIX CANONICALIZATION AND NOT AN ALIAS TABLE. Explicitly rejected by name: a
// SERVICEACCOUNT_PATH_ALIASES map, and special-casing this one mount the way /dev/termination-log
// is carved out above. That carve-out is justified by the agent OWNING that file's content, which
// is a different reason and does not generalize to "these two strings denote the same mount". This
// is a statement about a filesystem-layout convention, applied identically to every path on both
// sides of one comparison — it names no workload and no mount.
//
// It is deliberately NARROW. /var/run -> /run is the only rewrite, it is anchored at the start of
// the path, and it fires only on the exact component boundary (/var/run itself or /var/run/...) so
// a hypothetical /var/runtime is untouched. It cannot make two genuinely different mounts collide
// that the kernel itself distinguishes, because /var/run and /run are the same directory on any
// image where this fires. Applied to both sides, it is a no-op wherever the two already agreed.
func normalizeContainerMountPath(p string) string {
	const legacy = "/var/run"
	if p == legacy {
		return "/run"
	}
	if strings.HasPrefix(p, legacy+"/") {
		return "/run" + strings.TrimPrefix(p, legacy)
	}
	return p
}

// ---------------------------------------------------------------------------------------------
// D9 — host-namespace realpath confinement for runtime-supplied --ext-mount-map targets.
// ---------------------------------------------------------------------------------------------

// hostRealpathFn is a test seam over the typed netns-broker host_realpath op (ADR-0419 D9).
//
// It exists because D3+D4 change the PROVENANCE of validateExtMountToken's input: the anchor set
// resolvedHostTargets moves from a closed, agent-constructed four-entry table to
// runtimeMounts[].Source, with the checkpoint's own mountpoints image — attacker-influenceable
// under this codebase's own stated threat model — deciding which runtime entries are admitted. The
// set widens, its members become host paths the agent never constructed, and ADR-0417's only
// host-namespace read on any member (resolveDestinationRebindTargetsOnce / hostRegularFileExists)
// is deleted by this same ADR. ADR-0351 — the plumbing pattern D1 copies — confines an NRI-supplied
// string by EvalSymlinks-then-fail-CLOSED-then-prefix-check-the-RESOLVED-path; this copies that
// confinement, not only that plumbing.
//
// It is ONE typed read of ONE value at argv-construction time, not a poll: it reinstates no
// bounded wait and no `sh -c '[ -f ... ]'` chain.
var hostRealpathFn = func(target string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return netnsbroker.NewClient().HostRealpath(ctx, target)
}

// errExtMountRealpathUnresolved marks the fail-CLOSED leg so callers and tests can classify it.
var errExtMountRealpathUnresolved = errors.New("--ext-mount-map host target realpath could not be resolved in the host mount namespace")

// confineExtMountTargetRealpath resolves target in the HOST mount namespace and requires the
// RESOLVED path to sit under an allowed destination prefix.
//
// FAIL CLOSED on unresolvable, matching ADR-0351's confinement. The branch this replaces read
// `if real, err := filepath.EvalSymlinks(target); err == nil && real != target` — on resolve error
// the entire escape check was SKIPPED. That fail-open was already dead code for the two prefixes
// that matter: the agent's DaemonSet mounts no /var/lib/kubelet and carries no containerd CRI
// sandbox tree, so EvalSymlinks ALWAYS errored for them and only the agent-staged
// /var/lib/podmotion prefix ever received a real check.
func confineExtMountTargetRealpath(key, target string) error {
	real, err := hostRealpathFn(target)
	if err != nil {
		return fmt.Errorf("%w: target %q for key %q: %v — refusing (ADR-0419 D9: an unverifiable target is rejected, never admitted; CRIU resolves this path in the host mount namespace, so a confinement check that cannot read that namespace is not a check)", errExtMountRealpathUnresolved, target, key, err)
	}
	for _, p := range extMountTokenPrefixesFn() {
		if strings.HasPrefix(real, p) {
			return nil
		}
	}
	return fmt.Errorf("--ext-mount-map host target %q for key %q resolves in the host mount namespace to %q, which is outside every allowed destination prefix", target, key, real)
}

// ---------------------------------------------------------------------------------------------
// Instrumentation.
// ---------------------------------------------------------------------------------------------

// destinationRebindObserveFn is a test seam (mirrors sandboxWaitObserveFn), invoked exactly once
// per appendDestinationRebindReattachMounts call with the attempt count, elapsed time, and the
// outcome, so the resolver stays assertable from tests without parsing log output.
//
// ADR-0419 replaces ADR-0417's timing-shaped vocabulary ("resolved" | "never" | "probe_failed")
// with a fact-shaped one, because the outcomes it named no longer exist:
//
//	"resolved"              — every demanded mount resolved to a runtime-supplied Source.
//	"not_demanded"          — this checkpoint demands no DESTINATION-REBIND mount at all. The
//	                          outcome ADR-0417's hardcoded table structurally could not produce.
//	"runtime_mount_absent"  — a demanded mount has no entry in the runtime's own mount list (D3).
//	"runtime_lookup_failed" — the gRPC path's typed lookup failed terminally or never converged
//	                          (D5.3). Recorded honestly as a DELIBERATE addition beyond the three
//	                          tokens the removal-symmetry audit enumerates: that row predates the revision
//	                          2 introduced the D5.3 NEVER terminal, and folding that terminal into
//	                          "runtime_mount_absent" would conflate "the runtime told us this
//	                          container has no such mount" with "the runtime never answered" — the
//	                          precise conflation root cause (D) exists to prevent.
//
// No consumer outside this package (verified repo-wide), so the vocabulary change is contained.
var destinationRebindObserveFn = func(migrationName string, attempts int, elapsed time.Duration, outcome string) {}
