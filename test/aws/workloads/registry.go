// Package workloads registers the 8 gate-run workload types and provides
// manifest path helpers consumed by the gate harness.
//
// All 8 workload IDs (W1–W8) must be present in every gate run per ADR-0110 §3.
// Manifest layout:
//
//	test/aws/workloads/<wid>/workload.yaml  — pod under test
//	test/aws/workloads/<wid>/client.yaml    — load-generator client pod
package workloads

import "strings"

// WorkloadID identifies a workload type in the gate run.
type WorkloadID string

const (
	W1StatelessWeb        WorkloadID = "W1"
	W2PostgreSQL          WorkloadID = "W2"
	W3Redis               WorkloadID = "W3"
	W4NATSBroker          WorkloadID = "W4"
	W5GRPCStreaming        WorkloadID = "W5"
	W6WebSocket           WorkloadID = "W6"
	W7MultiContainerEnvoy WorkloadID = "W7"
	W8LongRunningCompute  WorkloadID = "W8"
)

// AllWorkloads returns the ordered list of workload IDs for a gate run.
// All 8 must be present per ADR-0110 §3.
func AllWorkloads() []WorkloadID {
	return []WorkloadID{
		W1StatelessWeb,
		W2PostgreSQL,
		W3Redis,
		W4NATSBroker,
		W5GRPCStreaming,
		W6WebSocket,
		W7MultiContainerEnvoy,
		W8LongRunningCompute,
	}
}

// ManifestPath returns the path to the workload manifest for w.
func ManifestPath(w WorkloadID) string {
	return "test/aws/workloads/" + strings.ToLower(string(w)) + "/workload.yaml"
}

// ClientManifestPath returns the path to the client manifest for w.
func ClientManifestPath(w WorkloadID) string {
	return "test/aws/workloads/" + strings.ToLower(string(w)) + "/client.yaml"
}
