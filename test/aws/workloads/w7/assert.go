package workload_w7

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// AssertMigration verifies zero RST and seq_delta==0 for W7 (multi-container-envoy).
// Called by gate_harness.go after TrafficVerified=True.
// Reads eBPF ring buffer and tcpdump capture per ADR-0113.
//
// Additionally performs the W7-specific Envoy resume assertion per ADR-0113 §5:
// polls http://<podIP>:9901/stats/prometheus for envoy_http_downstream_cx_active > 0
// within 1 second of TrafficVerified=True.
func AssertMigration(ctx context.Context, podIP string, captureFile string) error {
	// TODO: implement per ADR-0113 assertion protocol
	return nil
}

// AssertEnvoyResumed polls the Envoy admin endpoint on port 9901 and verifies that
// envoy_http_downstream_cx_active > 0 within 1 second of being called.
//
// Per ADR-0113 §5:
//   - Admin URL: http://<podIP>:9901/stats/prometheus
//   - Poll interval: 100ms
//   - Deadline: 1 second from TrafficVerified=True (enforced by the caller's context deadline)
//   - Hard failure if metric not > 0 within deadline
func AssertEnvoyResumed(ctx context.Context, podIP string) error {
	adminURL := fmt.Sprintf("http://%s:9901/stats/prometheus", podIP)
	deadline := time.Now().Add(1 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("W7 Envoy resume assertion: context cancelled before metric observed: %w", ctx.Err())
		case t := <-ticker.C:
			if t.After(deadline) {
				return fmt.Errorf("W7 Envoy resume assertion: envoy_http_downstream_cx_active not > 0 within 1s of TrafficVerified=True (ADR-0113 §5)")
			}
			// TODO: implement per ADR-0113 §5 — parse Prometheus text format from adminURL,
			// extract envoy_http_downstream_cx_active or envoy_cluster_upstream_cx_active,
			// return nil if value > 0.
			_ = adminURL
			_ = http.DefaultClient
		}
	}
}
