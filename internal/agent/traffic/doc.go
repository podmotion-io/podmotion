// Package traffic owns the traffic drain and verification pipeline.
//
// Responsibilities:
//   - EndpointSlice transition management (add new pod IP before removing old)
//   - AWS ALB/NLB target group registration, health check polling, and connection draining
//   - Traffic arrival verification via eBPF packet counter, Prometheus metrics, or webhook hook
//   - The TrafficVerified gate — must pass before source pod is deleted
//   - Old pod drain coordination (stop accepting new connections, let in-flight complete)
//
// Critical invariant: source pod is NEVER deleted until TrafficVerified=true.
// If trafficVerificationTimeoutSeconds expires without verification, rollback is triggered.
// Source pod was never stopped, so rollback is zero-downtime.
//
// Verification modes (in priority order for AWS PoC):
//   1. AWSALB  — target group registration + DescribeTargetHealth polling
//   2. EndpointSlice — explicit K8s endpoint transition management (always runs)
//   3. Metrics — configurable PromQL query against pod metrics
//   4. Hook    — user-provided webhook URL returning 200 OK
//   5. None    — explicit opt-in skip (operator acknowledges risk)
package traffic
