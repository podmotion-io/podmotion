# Upstream PR: MigrationBalance Plugin for kubernetes-sigs/descheduler

- **Target repo**: https://github.com/kubernetes-sigs/descheduler
- **Plugin type**: Balance
- **Author**: PodMotion Authors
- **Date**: 2026-06-09
- **Status**: Pre-proposal (design review needed before opening PR)

---

## Summary

This document describes the changes required in upstream `kubernetes-sigs/descheduler` to accept
the `MigrationBalance` plugin as a community-contributed Balance plugin.

The plugin currently lives at `descheduler/pkg/plugins/migrationbalance/plugin.go` in the
PodMotion repository and creates `PodMigration` CRs instead of evicting pods.  The upstream
descheduler's Balance interface uses `Evict()`; accepting MigrationBalance requires either:

1. A new `BalancePlugin` interface variant with `CreateMigration()`, or
2. Treating `PodMigration` CR creation as a form of "soft eviction" that the descheduler's
   eviction framework can handle through a pluggable eviction backend.

Option 2 is preferred for upstream acceptance because it requires fewer interface changes.

---

## Required Interface Change

### Current descheduler Balance interface

```go
// pkg/framework/types.go (upstream descheduler)
type BalancePlugin interface {
    Plugin
    Balance(ctx context.Context, pods []*v1.Pod) *Status
}
```

The `Balance` method is expected to call `handle.Evictor().Evict(ctx, pod, opts)` internally.
The `Evictor` interface today creates `Eviction` objects.

### Proposed addition

```go
// Migrator is an optional interface a BalancePlugin can implement to signal
// that it handles pod displacement via live migration rather than eviction.
// The descheduler framework checks for this interface before calling Balance();
// if present it calls Migrate() instead, passing the same Evictor handle so
// the plugin can still fall back to eviction when migration is unavailable.
type Migrator interface {
    Migrate(ctx context.Context, pods []*v1.Pod, evictor Evictor) *Status
}
```

The `MigrationBalance` plugin implements both `BalancePlugin` (for backwards compatibility) and
`Migrator` (for live-migration path).

---

## Dependency: PodMotion CRD Must Be Optional

The upstream descheduler cannot take a hard dependency on PodMotion CRDs.  The plugin must be
**feature-gated** so that clusters without PodMotion installed still work:

```go
// plugin.go — availability check at plugin instantiation
func New(args runtime.Object, h framework.Handle) (framework.Plugin, error) {
    if !isCRDInstalled(h.KubeClient(), "podmigrations.migration.podmotion.io") {
        // PodMotion not installed; fall back to no-op (plugin registers but does nothing)
        return &MigrationBalance{available: false}, nil
    }
    // ...
}
```

The descheduler config schema gains an optional `migrationBalance` section:

```yaml
profiles:
  - name: default
    pluginConfig:
      - name: MigrationBalance
        args:
          # podMotionEnabled controls whether PodMigration CRs are created.
          # When false (or PodMotion CRDs absent) the plugin silently no-ops.
          podMotionEnabled: true
          # imbalanceThreshold: migrate pods when node utilisation deviates from
          # mean by more than this fraction.
          imbalanceThreshold: "0.20"
          # maxMigrationsPerCycle caps the number of PodMigration CRs created
          # in a single descheduler Balance() invocation.
          maxMigrationsPerCycle: 5
```

---

## File Changes Required in Upstream Descheduler

| File | Change |
|---|---|
| `pkg/framework/types.go` | Add `Migrator` interface |
| `pkg/descheduler/descheduler.go` | Check for `Migrator`; call `Migrate()` if present |
| `pkg/plugins/migrationbalance/plugin.go` | New file (copy from PodMotion repo, strip vendored types) |
| `pkg/plugins/migrationbalance/plugin_test.go` | New file |
| `pkg/apis/componentconfig/v1alpha1/types.go` | Add `MigrationBalanceArgs` |
| `Makefile` | Add `migrationbalance` to `PLUGINS` variable |
| `README.md` | Document new plugin |

---

## Testing Requirements for Upstream Acceptance

The descheduler project requires the following before merging a new plugin:

### Unit tests

- [ ] `Balance()` returns no-op when `available: false` (CRD not installed).
- [ ] `Balance()` creates `PodMigration` CRs for over-utilised nodes.
- [ ] `Balance()` respects `maxMigrationsPerCycle`.
- [ ] `Balance()` skips pods with `migration.podmotion.io/exclude: "true"` annotation.
- [ ] `Migrate()` interface satisfied and callable through framework.

### Integration tests (kind cluster)

- [ ] Plugin does not crash when PodMotion operator is not installed.
- [ ] Plugin creates correct number of `PodMigration` CRs given simulated imbalance.
- [ ] Plugin does not re-migrate pods already in `Pending` or `Running` migration state.

### Conformance

- [ ] Plugin passes `descheduler e2e` suite without regressions.
- [ ] Plugin is listed in the descheduler plugin compatibility matrix.

---

## RBAC Required

The descheduler ServiceAccount must gain the following additional rules when MigrationBalance is
enabled:

```yaml
- apiGroups: ["migration.podmotion.io"]
  resources: ["podmigrations"]
  verbs: ["create", "get", "list", "watch"]
```

This is gated: the descheduler Helm chart only adds these rules when
`migrationBalance.podMotionEnabled=true`.

---

## Upstream PR Checklist

- [ ] Open issue on kubernetes-sigs/descheduler to gauge interest before coding.
- [ ] Attend WG Checkpoint/Restore meeting to introduce the concept.
- [ ] Send design doc to descheduler mailing list.
- [ ] Open draft PR with `Migrator` interface change only (small, reviewable).
- [ ] Follow with PR adding MigrationBalance plugin once interface is merged.
- [ ] Ensure CLA signed for all contributors.

---

## References

- [kubernetes-sigs/descheduler](https://github.com/kubernetes-sigs/descheduler)
- [descheduler Balance plugin guide](https://github.com/kubernetes-sigs/descheduler/blob/master/docs/user-guide.md)
- [PodMotion plugin.go](./plugin.go)
- [PodMotion ADR-0016: Gate ordering](../../../../../../docs/adr/ADR-0016-gate-ordering.md)
