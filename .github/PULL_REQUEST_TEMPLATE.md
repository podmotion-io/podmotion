## Summary

<!-- What does this PR do and why? Link any related issues with "Closes #123". -->

## Type of Change

- [ ] 🚀 Feature (non-breaking change that adds functionality)
- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] 📖 Documentation
- [ ] 🏗 Infrastructure / CI / build
- [ ] ⚠️ Breaking change (fix or feature that changes existing behavior; prefix the PR title with `BREAKING:`)

## Test Plan

<!-- How was this verified? Include commands, cluster setup, workload types, and observed results. -->

- [ ] `go test -race ./...` passes locally
- [ ] Manually verified against a kind/AWS cluster (describe below)

## Checklist

- [ ] Tests added or updated and passing
- [ ] `make manifests generate` run; no uncommitted drift
- [ ] Documentation updated (user-facing and/or `docs/`)
- [ ] An ADR was written if this introduces an architectural decision (`docs/adr/`)
- [ ] If breaking: migration path documented and `BREAKING:` prefix added to the title
- [ ] Security-sensitive paths (`bpf/`, `internal/agent/`, `pkg/nri/`, `pkg/restore/`) — security reviewer requested if touched
