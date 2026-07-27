/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package storage

import "errors"

// ErrRollbackPointOfNoReturn is returned by Migrator.ReleaseDestination when the forward
// Cutover already made an irrevocable choice — undo is not attempted, ever, for this
// migration. Reuses the exact name and semantics ADR-0086 §4 defined for this case (no
// contradiction found there — see ADR-0368 §4/§8). The caller MUST NOT retry a rollback step
// that returns this error (wrapped, per the tier's own message): the destination-side state is
// now authoritative and permanent.
//
// Mirrors the existing errEmptyDestinationNode sentinel pattern in tier1.go:36-37.
var ErrRollbackPointOfNoReturn = errors.New("storage rollback impossible: cutover already made an irrevocable change")

// ErrRollbackNotImplemented is returned by Migrator.ReleaseDestination when this tier's undo
// has not been built yet. Distinct from ErrRollbackPointOfNoReturn: this is a real, closeable
// gap, not a structural impossibility — but the caller must treat it exactly as loudly (see
// ADR-0368 §5.1/§6): the destination-side state was NOT verified released either way.
var ErrRollbackNotImplemented = errors.New("storage rollback not implemented for this tier: destination-side state was NOT verified released")
