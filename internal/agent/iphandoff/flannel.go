/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package iphandoff

// FlannelHandoff implements IPHandoffStrategy for Flannel CNI clusters.
//
// Flannel does not support IP mobility — pod IPs are allocated per-node from a
// per-node subnet and cannot be reassigned to a pod on a different node. There
// is no IPAM annotation mechanism or BGP-based host-route advertisement.
//
// When Flannel is detected, NetworkContinuity=true must be rejected at admission
// (ValidatingAdmissionWebhook) and at runtime (NetworkBridgeAgent.ArmBridge).
// Only cold migration (NetworkContinuity=false, TIER_4) is supported on Flannel
// clusters — TCP connections are not preserved across the migration.
type FlannelHandoff struct{}

// LiveMigrationEligible always returns false for Flannel. Called by the compat
// prober and the admission webhook to enforce the cold-migration-only policy.
func (f *FlannelHandoff) LiveMigrationEligible() bool { return false }

// Name returns the identifier used in logs and metrics.
func (f *FlannelHandoff) Name() string { return "flannel-cold-only" }
