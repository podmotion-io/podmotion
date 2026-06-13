# AWS Cost Plan — PodMotion Gate Runs

**Applies to:** M27 (single gate run) and M28 (80-run series)
**Authority:** ADR-0116 (Cost Controls and Teardown SLA)
**Last updated:** 2026-06-13

---

## Per-Run Cost Estimate

Each gate run provisions 2 clusters (1 EKS + 1 self-managed kubeadm) for a maximum of 4 hours.
All costs use us-east-1 on-demand pricing.

| Component | Detail | Estimated Cost |
|---|---|---|
| EKS control plane | 2 clusters × $0.10/hr × 4 hr | $0.80 |
| m7g.large worker nodes (arm64) | 2 nodes × $0.1626/hr × 4 hr | $1.30 |
| m7i.large worker nodes (x86-64) | 2 nodes × $0.1904/hr × 4 hr | $1.52 |
| m7i.large client node | 1 node × $0.1904/hr × 4 hr | $0.76 |
| Self-managed EC2 nodes (kubeadm) | 4 nodes × mixed m7g/m7i × 4 hr | ~$3.00 |
| EBS root volumes (node disks) | 5 nodes × 20 GiB gp3 × 4 hr | ~$3.00 |
| ENI secondary IPs (aws-vpc-cni) | ~5 per node × 5 nodes | ~$5.00 |
| Data transfer (inter-AZ) | Migration checkpoint payload × runs | ~$10.00 |
| NAT gateway data processing | Outbound traffic from private subnets | ~$2.00 |
| CloudWatch logs and metrics | Harness run log + node metrics | ~$2.00 |
| ELB and miscellaneous | Headroom for unexpected AWS charges | ~$15.00 |
| **Subtotal (estimated typical run)** | | **~$44–$55** |
| **2× safety margin** | Per ADR-0116 §5 | **$100–$110** |
| **Per-run budget cap** | Hard ceiling enforced by harness | **$200** |

Note: typical run cost is estimated at $85–$110 USD per the harness pre-run prompt (ADR-0116 §6).

---

## Cost Circuit-Breaker

- **Polling threshold:** $150 USD (75% of the $200 cap)
- **Poll interval:** every 30 minutes via AWS Cost Explorer `GetCostAndUsage` API
- **Scope:** resources tagged `podmotion:run-id=<run-uuid>`
- **Metric:** `BLENDED_COST`
- **Action on breach:** harness initiates immediate teardown; run marked `COST_EXCEEDED`

The $150 threshold leaves $50 of buffer to absorb Cost Explorer data lag (up to 30–60 minutes)
before the absolute $200 cap is reached.

---

## M27 Budget

- **Milestone:** M27 pre-beta gate (single qualifying run)
- **Runs:** 1
- **Maximum spend:** $200
- **Expected spend:** $85–$110

---

## M28 Budget Projection

- **Milestone:** M28 80-run randomized gate series
- **Runs:** 80
- **On-demand maximum:** 80 runs × $200/run = **$16,000**
- **Expected with spot instances:** 60–70% reduction once spot is enabled
  - Estimated: 80 × $85 × 0.35 spot discount ≈ **$4,760–$5,600**

Spot instances are **deferred to M28**. M27 uses on-demand only. Rationale: on-demand pricing
eliminates spot interruption as a variable in the first qualifying run, ensuring the pass/fail
result reflects PodMotion behavior rather than infrastructure instability. Reproducibility
requires on-demand for M27.

M28 spot instance design is tracked separately and requires a new ADR before implementation.

---

## Teardown SLA

All clusters must be fully torn down within **10 minutes** of harness exit (ADR-0116 §4).

- EKS deletion: typically 5–7 minutes
- kubeadm EC2 termination: typically 1–2 minutes
- Terraform VPC teardown: runs after cluster deletion completes

Teardown failure writes `test/aws/run_reports/teardown_failed.json` and emits a `ERROR teardown_failed`
line to stdout. Use `test/aws/cleanup_stale.sh` for manual recovery.

---

## Resource Tagging

All AWS resources are tagged for cost scoping and recovery:

| Tag | Value |
|---|---|
| `podmotion:run-id` | Run UUID (set per run by harness) |
| `podmotion:gate` | `m27` or `m28` |
| `podmotion:managed` | `true` |

---

## References

- ADR-0116 — AWS Cost Controls and Teardown SLA
- ADR-0111 — AWS Gate Cluster Provisioning Spec
- ADR-0110 — AWS Gate Run Topology and Pass/Fail Adjudication
- `test/aws/cleanup_stale.sh` — manual recovery for leaked resources
- `test/aws/run_reports/` — per-run cost and teardown artifacts

---

## Prior Planning Notes (pre-ADR-0116)

The following sections preserve the earlier local-first cost analysis that informed the M27 cluster
topology decisions. They are superseded by ADR-0116 for gate run budget enforcement.

**Status:** PLANNING — cost model for M27/M28 AWS proving
**Author role:** AWS cost-efficiency architect
**Date:** 2026-06-12
**Region anchor:** us-east-1 (N. Virginia), 2026 pricing
**North Star principle:** Keep all day-to-day development on local kind/VMs (free). Spin AWS up only for the hours a gate run actually needs, then tear it down. Target steady-state AWS spend ≈ **$0/month** with bursts of **$5–$40 per gate run**.

> All dollar figures are us-east-1 on-demand unless noted. Prices verified June 2026 (sources at end). Treat as ±10%; spot prices fluctuate.

---

## 0. TL;DR — One-sentence recommendation per decision point

| # | Decision | Recommendation |
|---|----------|----------------|
| 1 | GitHub Actions runners | Make the repo **public** when you push it — public repos get unlimited free GitHub-hosted minutes, which zeroes out CI cost entirely. |
| 2 | Multi-arch build | Drop QEMU; build arm64 **natively** on GitHub's free public `ubuntu-24.04-arm` runner (or your M4) and `docker manifest` the two together — cuts the arm64 leg from ~25 min to ~4 min. |
| 3 | M27 cluster | **Self-managed kubeadm on 2× c6i.xlarge spot** in public subnets, no EKS, no NAT — ~$0.27/hr total, gate run ≈ **$1–3**. |
| 4 | Spot vs on-demand | Use **spot** for build/soak nodes; pin the **migration source+target pair to on-demand** during the actual seq_delta=0 measurement window so an interruption can't invalidate the gate. |
| 5 | EKS vs kubeadm for M27 | **Skip EKS for M27** (it adds $0.10/hr cluster fee + VPC-CNI TCP limitation per ADR-0036); kubeadm + Calico is cheaper and matches the seq_delta=0 path. |
| 6 | Graviton (M28) | Add **2× c7g.xlarge spot** (~$0.10–0.14/hr) only during the M28 matrix; no separate cluster — reuse the same VPC. |
| 7 | M4 as CI node | Use the M4 as an **on-demand self-hosted arm64 runner via Tailscale**, started manually for release builds — but make the repo public first so it's a nice-to-have, not a dependency. |
| 8 | Region | **us-east-1** — cheapest list prices and where you'll do everything; us-west-2 is within ~1–2%, not worth splitting. |
| 9 | Networking | **Single VPC, public subnets only, no NAT Gateway** — saves the silent ~$32/mo + $0.045/GB NAT tax. |
| 10 | Registry | Stay on **GHCR** (free for public images); use ECR only if pull latency inside the gate cluster becomes a problem. |
| 11 | Checkpoint storage | **S3 Standard, same region, lifecycle-expire after 7 days** — pennies; never cross-region. |

---

## 1. GitHub Actions cost analysis

### 1.1 Current pipeline (all on GitHub-hosted `ubuntu-24.04`)
Workflows present: `ci.yaml`, `_build-image.yaml`, `nightly.yaml`, `test-e2e.yml`, `lint.yml`, `test.yml`, `release.yaml`, `agent-build.yaml`.

**2026 GitHub-hosted Linux pricing** (after the Jan 1 2026 price cut, incl. the $0.002 platform charge):
- Linux 2-core amd64: **$0.006/min**
- Linux 2-core **arm64: $0.005/min**
- **Free tier (private repo, Free plan): 2,000 Linux min/month.** Team plan: 3,000 min.
- **Public repos: unlimited free minutes on standard runners.** ← the single biggest lever.

**Estimated minute consumption per event (private-repo assumption):**

| Job | Est. minutes |
|-----|-------------|
| lint | 3 |
| unit tests (`test.yml`) | 5 |
| build-validate (`ci.yaml`) | 6 |
| e2e kind (`test-e2e.yml`) | 18 |
| **Per-PR subtotal** | **~32 min** |
| image build amd64 (`_build-image.yaml`) | 6 |
| image build arm64 **via QEMU** | **~25** |
| cosign + syft SBOM | 4 |
| **Per-merge subtotal (adds to PR)** | **~35 min** |

- **Per PR (push + reruns):** ~32 min × $0.006 ≈ **$0.19** (private) / **$0** (public).
- **Per merge to main:** ~67 min ≈ **$0.40** (private) / **$0** (public).
- **Nightly:** ~40 min/night × 30 ≈ 1,200 min/mo ≈ **$7.20/mo** (private) / **$0** (public).

### 1.2 The QEMU multi-arch build — the one real cost
`_build-image.yaml` builds `linux/arm64` under QEMU binfmt emulation on an amd64 host. Emulated arm64 Go/CGO-free builds still run **5–10× slower** than native; the arm64 leg dominates the workflow at ~25 min vs ~3–4 min native. Over a month of merges + nightlies this is the bulk of billable minutes.

**Better options, cheapest first:**
1. **Native arm64 GitHub-hosted runner** (`runs-on: ubuntu-24.04-arm`): free on public repos, $0.005/min on private. Build each arch on its own native runner in parallel, then `docker buildx imagetools create` / `docker manifest` to fuse the multi-arch index. arm64 leg drops to ~4 min. **No QEMU.**
2. **M4 self-hosted runner** for the arm64 leg (§4): $0 marginal compute, but adds an availability dependency.
3. Keep QEMU only as a fallback path.

Since binaries are **CGO-free cross-compiled via GOOS/GOARCH**, you don't even need native runners to produce the *binaries* — `GOARCH=arm64 go build` on amd64 is instant. QEMU is only needed if the *container image build itself* runs arch-specific steps. If the Dockerfile just `COPY`s a pre-cross-compiled binary, **you can build both arch images on a single amd64 runner with zero emulation** — just set the binary per `TARGETARCH`. This is the cheapest path of all.

> **Recommendation:** Cross-compile both binaries on one amd64 runner, `COPY` per-arch into a `buildx` multi-platform image with `--platform=linux/amd64,linux/arm64` using pre-built binaries (no per-arch RUN steps) — eliminates QEMU entirely and keeps the whole image job under ~8 min.

### 1.3 Free-tier limits & when you hit them
- Private repo, Free plan = 2,000 min/mo. Current nightly alone (~1,200 min) + ~20 PRs/mo (~640 min) ≈ **2,640 min → you blow the free tier in month one** and pay ~$4–8/mo overage.
- **Make the repo public** (it's an OSS project anyway — see MEMORY: "own public repos strategy") and **all standard-runner minutes are free, unlimited.** This is the recommended path and makes §1.1/§1.2 costs moot.

---

## 2. AWS minimum viable proving environment for M27

**Gate requirement (from VALIDATION_AND_CERTIFICATION_PLAN §3):** single CNI **Calico VXLAN/WireGuard** (seq_delta=0 capable), single OS **Ubuntu 24.04**, single arch **amd64**, **EBS gp3**. Note ADR-0036: **EKS VPC-CNI cannot guarantee TCP continuity** — so the seq_delta=0 path must run on Calico, which argues for self-managed kubeadm where you fully control the CNI and kernel.

### 2.1 Cluster shape
Minimum to migrate a pod from a source node to a target node = **1 control-plane + 2 workers**, or collapse to **2 nodes** (control-plane untainted as a worker + 1 dedicated worker). For a clean source→target migration use **3 small nodes** or **2 medium nodes**.

| Role | Instance | vCPU/RAM | On-demand $/hr | Spot $/hr (~) |
|------|----------|----------|----------------|---------------|
| Control-plane + source | c6i.xlarge / m6i.large | 4/8 or 2/8 | ~$0.17 / ~$0.10 | ~$0.06 / ~$0.035 |
| Worker (migration target) | c6i.xlarge | 4/8 | ~$0.17 | ~$0.06 |

c6i/m6i are **REQUIRED** primary classes in the plan (ENA 2.x, XDP_TX/REDIRECT). c6i.xlarge gives CRIU enough headroom for real workloads; m6i.large is fine for the North Star Redis/Postgres-scale proof.

### 2.2 Spot vs on-demand for CRIU gate runs
- CRIU checkpoint/restore is **stateful and time-sensitive**; a spot reclamation (2-min warning) **mid-checkpoint would corrupt or invalidate a gate measurement**.
- **Strategy:** run cluster bring-up, image pulls, and warm-up on **spot** (cheap). For the **actual measured migration window** (minutes), pin the **source and target nodes to on-demand** so AWS can't yank them. Everything else stays spot.
- Spot saves ~65% (c6i.xlarge $0.17 → ~$0.06). The on-demand premium only applies to the ~10-minute measurement window, costing cents.

### 2.3 EKS vs self-managed kubeadm for M27
| | EKS | kubeadm on EC2 |
|---|-----|----------------|
| Cluster fee | **+$0.10/hr** ($0.10 × 744 = $74/mo if left up) | $0 |
| CNI control | VPC-CNI default (TCP-continuity limited, ADR-0036); Calico needs overlay swap | Full control — install Calico WireGuard directly |
| Kernel/node-image control | Limited on MNG | Full (matters for CONFIG_MEM_SOFT_DIRTY validation, §3.7) |
| Setup time | ~15 min (`eksctl`) | ~20–30 min (`kubeadm init` + Calico) |
| M27 fit | Adds cost + the exact CNI limitation the gate avoids | **Best fit** |

> The plan §3.2 lists **both** EKS-MNG and self-managed as REQUIRED for M27+ — but for the **seq_delta=0 gate row specifically**, kubeadm+Calico is the correct and cheaper vehicle. Run EKS later as a *compatibility* check, not the gate itself.

**Recommendation:** M27 gate on **self-managed kubeadm**, 2× c6i.xlarge (1 spot + 1 on-demand during measurement), Calico with `wireguardEnabled: true`.

### 2.4 Hourly + per-gate cost (M27)
- Running cost: 2× c6i.xlarge spot ≈ **$0.12/hr** + gp3 (2× 30 GB ≈ $0.008/hr) + EBS/EIP trivial ≈ **~$0.13/hr all-in**.
- A gate run = bring-up + soak + measure + teardown ≈ **2–4 hours** → **$0.30–$0.55** on spot, **~$1.40** if entirely on-demand.
- Budget **$1–3 per M27 gate run** including data transfer and a safety margin.

### 2.5 Teardown strategy
- **Never leave it up.** Wrap bring-up/teardown in a script (`terraform apply`/`destroy` or `eksctl delete` / `kubeadm reset` + EC2 terminate).
- Tag everything `project=podmotion-gate`; a teardown script terminates by tag. Add an **AWS Budgets alarm at $20/mo** that emails you — catches a forgotten cluster (a left-up c6i.xlarge pair = ~$245/mo, the main surprise-cost risk).
- Optional: a **max-uptime auto-terminate Lambda** (or an `at`-scheduled `shutdown`) so a forgotten cluster self-destructs after N hours.

---

## 3. ARM64 / Graviton proving cost (M28)

M28 adds arm64. Plan §3.3 requires **c6g/m6g (Graviton2)** and **c7g/m7g (Graviton3)** for M28.

- CRIU needs kernel 5.15+ — **standard on Graviton2/3 with Ubuntu 22.04/24.04 and AL2023.** All three CRIU configs present.
- **Cheapest viable Graviton worker:** `m7g.large` (~**$0.082/hr** on-demand, ~$0.03 spot) or `c7g.large`. For headroom use `c7g.xlarge` (~**$0.145/hr** on-demand, ~$0.05 spot).
- **EKS-MNG Graviton vs self-managed:** same logic as §2.3 — self-managed kubeadm for the gate (full kernel control), EKS-MNG as a compatibility pass. No need for a separate cluster: **add Graviton nodes into the same VPC/subnet** as the amd64 run.

**Add-on cost vs amd64-only:** an M28 matrix run needs ~2 extra Graviton nodes for the arm64 leg. At spot ~$0.10/hr combined for 2–4 hrs = **~$0.20–$0.40 added per matrix run**. The matrix breadth (3 CNIs × 3 OS × 2 arch × EKS 1.29–1.31) multiplies *runs*, not hourly rate — see §5 Phase 2.

---

## 4. The M4 workstation as a build/CI node

### 4.1 Can the M4 run as a self-hosted arm64 runner?
Yes — Apple M4 is arm64; it can register as a self-hosted GitHub Actions runner and build **native linux/arm64 container images** inside Docker Desktop / Colima (linux/arm64 VM). This is genuinely native (no QEMU).

### 4.2 Savings vs QEMU
- QEMU arm64 leg ~25 min → native on M4 ~3–4 min. On a **public repo**, GitHub minutes are already free, so the saving is **wall-clock latency, not dollars**. On a private repo it'd save ~$0.10/merge.
- Verdict: the M4 runner is a **speed/optionality play, not a cost play** — only worth wiring up if `ubuntu-24.04-arm` hosted runners are unavailable or you want release builds on your own hardware.

### 4.3 Networking — receiving GitHub jobs
GitHub self-hosted runners **poll outbound** (long-poll HTTPS to github.com); **no inbound webhook, no port-forward, no static IP needed.** The runner behind your home NAT just works.
- **Tailscale** is still recommended — not for GitHub connectivity, but so the runner can reach the AWS gate cluster / local pm-control/pm-worker VMs on a private mesh if a job needs them.
- ngrok/static IP are **not required** for the runner itself.

### 4.4 Risk: workstation offline = CI breaks
- Mitigation 1: keep the M4 runner **non-default** — label it (`self-hosted, m4, arm64`) and only route *release/image* jobs to it; keep PR/test jobs on hosted runners so day-to-day CI never depends on your laptop being awake.
- Mitigation 2: add `ubuntu-24.04-arm` hosted runner as a fallback `runs-on` matrix entry.
- Mitigation 3 (note 2026 change): **self-hosted runners now incur a $0.002/min platform charge on private repos** (from Mar 1 2026) — another reason to keep the repo public, where self-hosted stays free.

> **Recommendation:** Don't make the M4 a CI dependency. Public repo + hosted arm64 runners is the zero-cost, zero-risk default; keep the M4 runner as an optional, manually-started node for local-network release builds.

---

## 5. Total cost model — local-first, AWS only for gate runs

### Phase 1 (now → M27): local development, AWS only for the gate
- Dev: 100% local kind + the existing pm-control/pm-worker VMs (192.168.252.x). **$0.**
- CI: public repo → **$0.**
- AWS: a handful of M27 dry-runs + the real gate. Say **10 gate/dry-run sessions × $2** = **$20 one-time**, spread over the phase.
- **Monthly AWS spend: ~$0–5/mo** (just incidental gate runs + S3 pennies).

### Phase 2 (M28): full-matrix AWS gate, 80 runs
- Matrix: 2 arch × 3 CNI × 3 OS × EKS 1.29–1.31 ≈ many combos; "80 runs" budget.
- Per run: small multi-node cluster (mix amd64 c6i + Graviton c7g), mostly spot, ~2 hrs each ≈ **$0.50–$1.50/run** compute. Add EKS cluster fee for the EKS-MNG compatibility subset (~$0.10/hr × 2 hr = $0.20 on those runs).
- **80 runs × ~$1.25 avg ≈ $100 total**, plus ~$10 S3/data transfer → **~$110 for the entire M28 AWS gate campaign.**
- If compressed into one month: **~$110/mo that month**, otherwise spread to **~$30–50/mo** across the M28 window.

### Phase 3 (M29+): CNCF sandbox & sponsored compute
- On CNCF Sandbox acceptance, pursue **CNCF Community Infrastructure Lab (CIL)** and cloud-provider OSS credits:
  - **AWS Promotional Credits for OSS / AWS Open Source program** — apply for credits once you have a public repo + traction.
  - **CNCF cluster/CIL access** for bare-metal and multi-arch hardware (incl. Equinix Metal-style donated capacity).
  - GitHub public-repo minutes already free.
- **Target Phase 3 out-of-pocket AWS: ~$0** (credit-funded), with on-demand gate bursts as backstop.

| Phase | Monthly AWS spend (out of pocket) |
|-------|-----------------------------------|
| Phase 1 (→M27) | **$0–5/mo** |
| Phase 2 (M28) | **$30–110/mo** during the campaign |
| Phase 3 (M29+) | **~$0** (CNCF/AWS OSS credits) |

---

## 6. Specific AWS resource recommendations

### 6.1 Region — us-east-1 vs us-west-2
- us-east-1 has the **lowest list prices** and broadest spot capacity; us-west-2 is within ~1–2% on these instance families. No meaningful saving in splitting.
- **Use us-east-1** for everything. Keep S3, EC2, and ECR all in-region to avoid **cross-region/internet data-transfer charges** ($0.09/GB egress is the silent killer).

### 6.2 VPC setup (proving environment)
- **Single VPC, single AZ, public subnets only.** Give nodes public IPs (or one EIP + the rest public-IP-on-launch) so they reach the internet via the **Internet Gateway (free)**.
- **DO NOT create a NAT Gateway** — it's ~$0.045/hr (~$32/mo) **plus** $0.045/GB processed, billed even when idle. This is the #1 surprise cost in throwaway clusters. Public subnets + IGW = $0.
- Security group: lock SSH/API to your home IP; allow node-to-node for VXLAN/WireGuard (UDP 4789 / 51820).
- **VPC itself, IGW, route tables, security groups = free.** EIP is free while attached to a running instance (charged only when idle/unattached).

### 6.3 EKS Free Tier / cluster fee
- There is **no free EKS control plane** — every EKS cluster is **$0.10/hr ($73/mo)** regardless of size. (EKS Auto Mode / Fargate add more.)
- **For M27: skip EKS entirely.** kubeadm = $0 control-plane fee and the CNI control you need (§2.3).
- For M28's EKS-MNG compatibility rows, create the EKS cluster, run the matrix subset, **delete it the same day** — $0.10/hr × a few hours = cents.

### 6.4 S3 for checkpoint images (during gate)
- **S3 Standard, us-east-1: ~$0.023/GB-month.** CRIU checkpoint images for the North Star workloads are MB-to-low-GB; even 50 GB = ~$1.15/mo.
- **Same-region S3 ↔ EC2 transfer is free.** Cross-region/internet is not — keep the bucket in us-east-1.
- Config: private bucket, SSE-S3 encryption, **lifecycle rule to expire objects after 7 days** so gate artifacts don't accumulate. Optionally S3 One Zone-IA for even cheaper short-lived storage.
- Requests are negligible (PUT $0.005/1k, GET $0.0004/1k).

### 6.5 ECR vs GHCR
- **GHCR:** free for public images, integrates with the public-repo CI, no per-GB storage bill. **Default choice.**
- **ECR:** $0.10/GB-month storage + same-region pull to EC2 is free (cross-region/internet egress charged). Only switch to ECR if in-cluster pull latency or GHCR rate limits hurt a gate run; you can mirror just the gate image to ECR on the fly.
- **Recommendation:** GHCR primary; ad-hoc ECR mirror only if a gate needs faster/in-VPC pulls.

---

## 7. Surprise-cost watchlist

| Item | Cost | Mitigation |
|------|------|-----------|
| NAT Gateway | ~$32/mo + $0.045/GB, idle-billed | **Don't create one** — public subnets + IGW |
| EKS control-plane fee | $0.10/hr = $73/mo if left up | Skip EKS for M27; delete same-day for M28 |
| Forgotten running cluster | c6i.xlarge pair ≈ $245/mo | Tag + teardown script + $20 AWS Budgets alarm + auto-terminate |
| Cross-region / internet data transfer | $0.09/GB egress | Keep S3/ECR/EC2 all in us-east-1; no cross-region copies |
| Unattached EIP | ~$3.60/mo each | Release EIPs at teardown |
| Spot reclaim mid-checkpoint | invalid gate, wasted run | On-demand only during the measured migration window |
| GitHub private-repo Actions overage | ~$4–8/mo | Make the repo public |
| Self-hosted runner platform charge (Mar 2026) | $0.002/min on private repos | Public repo (self-hosted stays free) |

---

## Sources
- [GitHub Actions 2026 pricing changes](https://resources.github.com/actions/2026-pricing-changes-for-github-actions/) and [GitHub Actions billing docs](https://docs.github.com/billing/managing-billing-for-github-actions/about-billing-for-github-actions)
- [GitHub Actions runner pricing reference](https://docs.github.com/en/billing/reference/actions-runner-pricing) (arm64 2-core $0.005/min)
- [c7i.2xlarge pricing — Vantage](https://instances.vantage.sh/aws/ec2/c7i.2xlarge) ($0.357 on-demand / $0.17 spot)
- [c7g.xlarge pricing — economize.cloud](https://www.economize.cloud/resources/aws/pricing/ec2/c7g.xlarge/) ($0.145/hr) and [m7g.large — Vantage](https://instances.vantage.sh/aws/ec2/m7g.large) ($0.0816/hr)
- [Amazon EC2 On-Demand pricing](https://aws.amazon.com/ec2/pricing/on-demand/)
- PodMotion `docs/VALIDATION_AND_CERTIFICATION_PLAN.md` §3 (instance families, CNI, OS, EKS matrix; ADR-0036 VPC-CNI TCP limitation)
