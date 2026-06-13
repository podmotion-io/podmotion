package ci

// gate.go — CI release gate logic.
// Canonical specification: ADR-0093 (formerly ADR-0079), §3 and §4.
// RequiredConsecutiveGreenRuns is the ONLY place this constant lives;
// all tooling must import it from here.

const (
	// RequiredConsecutiveGreenRuns is the number of consecutive green runs
	// required on ALL required-tier cells before a release artifact is promoted.
	// ADR-0093 §3.
	RequiredConsecutiveGreenRuns = 10

	// ClearanceWindowSize is the rolling window size (in runs) used for flake
	// rate measurement. ADR-0093 §2.2.
	ClearanceWindowSize = 30

	// NorthStarRecoveryRuns is the number of consecutive green runs required
	// after a TCPREPAIR_RECOVERY_STREAK_INSUFFICIENT violation before the cell
	// is considered recovered. A single Phase 2 (TCP_REPAIR) failure requires
	// this many clean consecutive runs before promotion is unblocked.
	// ADR-0093 §5.
	NorthStarRecoveryRuns = 3
)

// GateViolation codes.
const (
	// ViolationInsufficientStreak is emitted when a required-tier cell has
	// current_streak < RequiredConsecutiveGreenRuns.
	ViolationInsufficientStreak = "INSUFFICIENT_STREAK"

	// ViolationFlakeBudgetExceeded is emitted when flake_rate > 0.02 for a
	// required-tier cell with no valid quarantine entry.
	ViolationFlakeBudgetExceeded = "FLAKE_BUDGET_EXCEEDED"

	// ViolationTCPRepairRecoveryStreakInsufficient is emitted when a Phase 2
	// (TCP_REPAIR) errsDuringMigration > 0 failure was recorded and the
	// cell has not yet accumulated NorthStarRecoveryRuns consecutive green
	// runs since the failure. This is the direct expression of the North Star
	// invariant (seq_delta=0; ALL clients unaware).
	// ADR-0093 §5.
	ViolationTCPRepairRecoveryStreakInsufficient = "TCPREPAIR_RECOVERY_STREAK_INSUFFICIENT"

	// ViolationKernelConfigMissing is emitted when check-kernel-config.sh
	// exits non-zero on a required-tier kernel.
	ViolationKernelConfigMissing = "KERNEL_CONFIG_MISSING"

	// ViolationDeterministicFailure is emitted when a test in
	// live_migration_traffic_test.go fails on two consecutive runs of the
	// same required-tier cell with no code change between runs.
	ViolationDeterministicFailure = "DETERMINISTIC_FAILURE"

	// ViolationStorageNetworkGateFailure is emitted when StorageReadyForFreeze,
	// NetworkBridgeArmed, or TrafficVerified conditions are False at completion.
	ViolationStorageNetworkGateFailure = "STORAGE_NETWORK_GATE_FAILURE"

	// ViolationDataPending is emitted when a required-tier cell has fewer than
	// RequiredConsecutiveGreenRuns recorded runs (bootstrap gap policy).
	ViolationDataPending = "DATA_PENDING"
)

// GateViolation describes a single release-blocking or warning condition.
type GateViolation struct {
	Code    string `json:"code"`    // e.g. "INSUFFICIENT_STREAK", "FLAKE_BUDGET_EXCEEDED"
	CellID  string `json:"cell_id"` // "<kernel>/<cni>/<storage>/<k8s>"
	Message string `json:"message"`
}

// GateResult is the output of check-release-gate.
type GateResult struct {
	// Blocking is non-empty when release promotion must be stopped.
	Blocking []GateViolation `json:"blocking,omitempty"`
	// Warnings is non-empty for non-blocking issues that must be tracked.
	Warnings []GateViolation `json:"warnings,omitempty"`
	// ReadyForPromotion is true only when Blocking is empty and all
	// required-tier cells have current_streak >= RequiredConsecutiveGreenRuns.
	ReadyForPromotion bool `json:"ready_for_promotion"`
}

// IsReleaseBlocking returns true when the GateResult has any blocking violations.
func (r *GateResult) IsReleaseBlocking() bool {
	return len(r.Blocking) > 0
}

// AddBlocking appends a blocking violation to the GateResult and ensures
// ReadyForPromotion is false.
func (r *GateResult) AddBlocking(code, cellID, message string) {
	r.Blocking = append(r.Blocking, GateViolation{
		Code:    code,
		CellID:  cellID,
		Message: message,
	})
	r.ReadyForPromotion = false
}

// AddWarning appends a non-blocking warning to the GateResult.
func (r *GateResult) AddWarning(code, cellID, message string) {
	r.Warnings = append(r.Warnings, GateViolation{
		Code:    code,
		CellID:  cellID,
		Message: message,
	})
}

// EvaluateStreak evaluates a single cell's green streak against the gate
// threshold and adds a blocking violation if the streak is insufficient.
// streak < 0 signals that the cell is in data-pending state (< 10 recorded runs).
func (r *GateResult) EvaluateStreak(cellID string, streak int) {
	if streak < 0 {
		r.AddBlocking(ViolationDataPending, cellID,
			"cell has fewer than "+itoa(RequiredConsecutiveGreenRuns)+
				" recorded runs; bootstrap gap policy blocks promotion until data is available")
		return
	}
	if streak < RequiredConsecutiveGreenRuns {
		r.AddBlocking(ViolationInsufficientStreak, cellID,
			"current_streak="+itoa(streak)+
				" < required "+itoa(RequiredConsecutiveGreenRuns))
	}
}

// itoa is a minimal int-to-string helper to avoid importing strconv in this
// gate logic file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
