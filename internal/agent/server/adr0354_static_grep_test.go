// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The PodMotion Authors

package server

// adr0354_static_grep_test.go — D6.3 (ADR-0354 §"Named regression tests").
//
// Static/grep-level assertion, mirroring the existing precedent in this codebase
// (internal/agent/netnsbroker/adr0347_test.go's TestNetnsExec_RoutesThroughBrokerNotDirectAgentNsenter,
// which reads server.go's own source and regexes it for a structural regression) that no
// broker-exec shim or call site on the restore path has regressed back onto a fresh
// context.Background()/context.TODO()-rooted budget.
//
// See docs/adr/0354-restore-broker-exec-caller-deadline-binding.md.

import (
	"os"
	"regexp"
	"testing"
)

// readServerGoSource reads this package's server.go — the file every ADR-0354 D6.3 assertion
// below inspects.
func readServerGoSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	return string(b)
}

// extractFuncBody returns the source text from a function's `func ... {` signature line
// (matched by sigPattern) up to the matching top-level closing brace — i.e. the function body,
// found by brace-depth counting from the opening `{`. Fails the test if sigPattern does not
// match exactly once, or if braces never balance.
func extractFuncBody(t *testing.T, src, sigPattern string) string {
	t.Helper()
	re := regexp.MustCompile(sigPattern)
	locs := re.FindAllStringIndex(src, -1)
	if len(locs) != 1 {
		t.Fatalf("expected exactly one match for signature pattern %q in server.go, got %d", sigPattern, len(locs))
	}
	start := locs[0][0]
	// Find the opening brace of the function body at/after the signature match.
	openIdx := -1
	for i := locs[0][1] - 1; i < len(src); i++ {
		if src[i] == '{' {
			openIdx = i
			break
		}
	}
	if openIdx == -1 {
		t.Fatalf("could not find opening brace for function matching %q", sigPattern)
	}
	depth := 0
	for i := openIdx; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1]
			}
		}
	}
	t.Fatalf("braces never balanced for function matching %q", sigPattern)
	return ""
}

// TestNoBackgroundContextInBrokerExecShims is ADR-0354 D6.3.
func TestNoBackgroundContextInBrokerExecShims(t *testing.T) {
	src := readServerGoSource(t)

	// The exact D1/D2/D2b anti-pattern this ADR retires: a broker-exec shim minting its OWN
	// fresh budget rooted on context.Background()/context.TODO() instead of the caller ctx —
	// see the ADR's own pre-fix quote: `context.WithTimeout(context.Background(), brokerExecTimeout)`.
	// Grepping for this specific construction (rather than any bare mention of
	// context.Background()) deliberately does not flag brokerCmd.result()'s defensive
	// `callerCtx = context.Background()` nil-guard fallback (only reachable if a FUTURE call
	// site bypasses nsenterCmd entirely, which the nsenterCmd/newBrokerCriuCmd call-site checks
	// below independently guard against) — it targets the actual defect: an RPC ctx rooted on
	// Background()/TODO() rather than derived from the caller's ctx.
	rootingRe := regexp.MustCompile(`context\.WithTimeout\(\s*context\.(Background|TODO)\(\)`)

	t.Run("brokerCmd.result() does not root its RPC ctx in Background()/TODO()", func(t *testing.T) {
		body := extractFuncBody(t, src, `func \(b \*brokerCmd\) result\(\)`)
		if m := rootingRe.FindAllString(body, -1); len(m) != 0 {
			t.Fatalf("result() roots its RPC ctx in context.Background()/TODO(): %v", m)
		}
	})

	for _, method := range []string{`Start`, `poll`, `Signal`} {
		method := method
		t.Run("brokerCriuCmd."+method+"() does not root its RPC ctx in Background()/TODO()", func(t *testing.T) {
			sig := `func \(c \*brokerCriuCmd\) ` + method + `\(`
			body := extractFuncBody(t, src, sig)
			if m := rootingRe.FindAllString(body, -1); len(m) != 0 {
				t.Fatalf("%s() roots its RPC ctx in context.Background()/TODO(): %v", method, m)
			}
		})
	}

	t.Run("no nsenterCmd call site passes Background()/TODO() as the ctx argument", func(t *testing.T) {
		re := regexp.MustCompile(`nsenterCmd\(\s*context\.(Background|TODO)\(\)`)
		if m := re.FindAllString(src, -1); len(m) != 0 {
			t.Fatalf("found %d nsenterCmd call site(s) passing Background()/TODO() as ctx: %v", len(m), m)
		}
	})

	t.Run("no newBrokerCriuCmd call site passes Background()/TODO() as the ctx argument", func(t *testing.T) {
		re := regexp.MustCompile(`newBrokerCriuCmd\(\s*context\.(Background|TODO)\(\)`)
		if m := re.FindAllString(src, -1); len(m) != 0 {
			t.Fatalf("found %d newBrokerCriuCmd call site(s) passing Background()/TODO() as ctx: %v", len(m), m)
		}
	})

	t.Run("no restore-path NetnsExec/NetnsExecStart call site passes Background()/TODO()", func(t *testing.T) {
		// D2c / round-2 completeness extension: the netns_exec family funnels the same
		// Client.do(ctx) as Exec/ExecStart/ExecPoll/ExecSignal — this file's twelve
		// NetnsExec/NetnsExecStart call sites (server.go, enumerated in ADR-0354 DR-5/DR-7)
		// must never regress onto a Background()/TODO()-rooted ctx argument, exactly as the
		// two former holdouts (loopback-up, veth-peer resolve) were swept by D2c.
		re := regexp.MustCompile(`\.NetnsExec(Start)?\(\s*context\.(Background|TODO)\(\)`)
		if m := re.FindAllString(src, -1); len(m) != 0 {
			t.Fatalf("found %d NetnsExec/NetnsExecStart call site(s) in server.go passing Background()/TODO(): %v", len(m), m)
		}
	})
}
