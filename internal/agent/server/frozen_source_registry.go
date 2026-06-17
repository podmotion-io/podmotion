package server

// frozen_source_registry.go — durable on-disk registry of source PIDs left in
// SIGSTOP by LeaveStopped=true CRIU dumps, plus a startup reconciliation that
// thaws orphaned frozen sources after an agent restart.
//
// ADR-0216 (Sprint 35 Phase C, gate attempt 12 origin).
//
// WHY (ADR-0216): The in-memory frozenSourcePIDs map (server.go) is the only
// record that a source workload is in SIGSTOP. Thaw is wired on every error /
// rollback / Abort path, but that thaw can ONLY fire from the SAME agent process
// that registered the freeze. When the agent pod restarts AFTER a LeaveStopped
// dump but BEFORE the matching SIGCONT (Abort/rollback/InjectIPHandoff), the
// in-memory registration is lost and no SIGCONT is ever delivered — the source
// workload stays frozen forever (State: T). Gate-12 observed exactly this: the
// gate-redis-s35 server (PID 1, State T) was listening but never returned PONG;
// a manual `kill -CONT 1` immediately restored PONG. The agent pods were 15m old
// while the frozen redis was 92m old — the agent that registered the freeze had
// been recreated, taking the volatile registry with it. SIGCONT (thaw) is the
// active-but-silent mechanism: present and correct, but unable to fire across an
// agent restart because its registry is not durable.
//
// FIX (ADR-0216, bounded to the first active-but-silent mechanism — the thaw):
//   1. Mirror every registerFrozenSource / clearFrozenSource to an on-disk JSON
//      record under /run/podmotion/frozen-sources/ (hostPath, survives agent pod
//      restart; cleared only on node reboot, which also kills the frozen process).
//   2. On agent startup, ReconcileOrphanedFrozenSources() reads those records and
//      SIGCONTs any source still in State T — guarded by a PID+starttime identity
//      check so a reused PID is never signalled.
//
// PID-reuse safety: a bare PID is not a stable identity (the kernel reuses PIDs).
// Each record stores the process start-time (field 22 of /proc/<pid>/stat,
// in clock ticks since boot). Reconcile thaws ONLY when the live process at that
// PID has the SAME start-time AND is in State T (stopped). Any mismatch ⇒ the
// original process is gone ⇒ the record is stale ⇒ delete it, never signal.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// frozenSourceDir is the hostPath-backed directory where frozen-source records
// are persisted. /run/podmotion is a hostPath mount (charts daemonset.yaml), so
// records survive an agent POD restart. /run/podmotion/checkpoints is a nested
// tmpfs; frozen-sources is a sibling of it and is NOT tmpfs, so it persists.
// On node reboot the whole tree is cleared — acceptable, because a node reboot
// also terminates the frozen process (the record would be stale anyway).
const frozenSourceDir = "/run/podmotion/frozen-sources"

// frozenSourceRecord is the durable form of one frozenSourcePIDs map entry.
type frozenSourceRecord struct {
	MigrationName string `json:"migrationName"`
	PID           int32  `json:"pid"`
	// StartTimeTicks is field 22 of /proc/<pid>/stat at registration time. It is
	// the PID-reuse guard: reconcile thaws only if the live PID's start-time matches.
	StartTimeTicks uint64 `json:"startTimeTicks"`
}

// frozenSourceRecordPath returns the on-disk path for a migration's record.
// The migration name is sanitised so it cannot escape frozenSourceDir.
func frozenSourceRecordPath(migrationName string) string {
	safe := strings.NewReplacer("/", "_", "..", "_", string(os.PathSeparator), "_").Replace(migrationName)
	return filepath.Join(frozenSourceDir, safe+".json")
}

// readProcStartTime returns field 22 (starttime, clock ticks since boot) from
// /proc/<pid>/stat. The second field (comm) may contain spaces and parentheses,
// so we parse from the last ')' to avoid mis-splitting on the command name.
func readProcStartTime(pid int32) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return 0, err
	}
	s := string(data)
	rparen := strings.LastIndex(s, ")")
	if rparen < 0 || rparen+2 >= len(s) {
		return 0, os.ErrInvalid
	}
	// Fields after comm: state is fields[0] (overall field 3). starttime is
	// overall field 22 ⇒ index 19 in the post-comm slice.
	fields := strings.Fields(s[rparen+2:])
	const startTimeIdx = 19
	if len(fields) <= startTimeIdx {
		return 0, os.ErrInvalid
	}
	return strconv.ParseUint(fields[startTimeIdx], 10, 64)
}

// procIsStopped reports whether the process at pid is in State 'T' (stopped),
// i.e. left in SIGSTOP by --leave-stopped.
func procIsStopped(pid int32) (bool, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return false, err
	}
	s := string(data)
	rparen := strings.LastIndex(s, ")")
	if rparen < 0 || rparen+2 >= len(s) {
		return false, os.ErrInvalid
	}
	fields := strings.Fields(s[rparen+2:])
	if len(fields) == 0 {
		return false, os.ErrInvalid
	}
	return fields[0] == "T", nil
}

// persistFrozenSource writes the durable record for a freeze registration.
// Best-effort: a write failure is logged by the caller but does not abort the
// migration — the in-memory map still provides same-process thaw coverage.
func persistFrozenSource(migrationName string, pid int32) error {
	if err := os.MkdirAll(frozenSourceDir, 0o700); err != nil {
		return err
	}
	startTicks, err := readProcStartTime(pid)
	if err != nil {
		// Without a start-time we cannot make reconcile PID-reuse-safe; record 0
		// so reconcile treats any live State-T process at this PID as a match only
		// when it also reads 0 (i.e. never, on a real kernel) — fail closed.
		startTicks = 0
	}
	rec := frozenSourceRecord{MigrationName: migrationName, PID: pid, StartTimeTicks: startTicks}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	// Atomic write: temp + rename so a crash mid-write never leaves a torn record.
	tmp := frozenSourceRecordPath(migrationName) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, frozenSourceRecordPath(migrationName))
}

// removeFrozenSourceRecord deletes the durable record for a migration.
// Idempotent: a missing record is not an error.
func removeFrozenSourceRecord(migrationName string) {
	_ = os.Remove(frozenSourceRecordPath(migrationName))
}

// ReconcileOrphanedFrozenSources scans the durable registry at agent startup and
// SIGCONTs any source process that is still in State T with a matching start-time.
// This closes the cross-restart thaw gap (ADR-0216): a freeze registered by a
// now-dead agent process is thawed here so the source workload resumes.
//
// Disposition per record:
//   - PID/stat unreadable (process gone)            ⇒ stale ⇒ remove record.
//   - start-time mismatch (PID reused)              ⇒ stale ⇒ remove record, NEVER signal.
//   - State != T (already running / thawed)          ⇒ done ⇒ remove record.
//   - State == T and start-time matches              ⇒ orphan ⇒ SIGCONT, then remove record.
//
// Returns the number of processes actually thawed (for startup logging/metrics).
func ReconcileOrphanedFrozenSources() (thawed int) {
	entries, err := os.ReadDir(frozenSourceDir)
	if err != nil {
		// Directory absent ⇒ nothing was ever frozen on this node. Not an error.
		return 0
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(frozenSourceDir, e.Name())
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var rec frozenSourceRecord
		if json.Unmarshal(b, &rec) != nil || rec.PID <= 0 {
			_ = os.Remove(path) // unparseable ⇒ stale
			continue
		}
		liveStart, stErr := readProcStartTime(rec.PID)
		if stErr != nil {
			_ = os.Remove(path) // process gone
			continue
		}
		if liveStart != rec.StartTimeTicks {
			_ = os.Remove(path) // PID reused — never signal a different process
			continue
		}
		stopped, stopErr := procIsStopped(rec.PID)
		if stopErr != nil {
			_ = os.Remove(path)
			continue
		}
		if !stopped {
			_ = os.Remove(path) // already running — nothing to thaw
			continue
		}
		// Orphaned frozen source confirmed (same PID, same start-time, State T).
		if killErr := syscall.Kill(int(rec.PID), syscall.SIGCONT); killErr == nil {
			thawed++
		}
		_ = os.Remove(path)
	}
	return thawed
}
