# Why PodMotion: The Case for Live Pod Migration

## The goal, stated plainly

Every container in the pod continues running. Unaware it moved.

Every client with an open connection continues unaware. No RST. No reconnect. No retry.

Not "the connection survives through reconnect logic." Not "the main container survives."
Every container. Every client. Zero awareness. That is the bar.

This is what live VM migration (OpenStack Nova live migration, live VM migration) achieves at the
VM layer. PodMotion achieves it at the pod layer, on stock Kubernetes, on stock kernels, with
no changes to the application and no changes to the client.

---

## The community was half right

For years the Kubernetes community maintained that live pod migration is unnecessary.
The argument: design stateless services, use persistent volumes with RWX access, let the
scheduler reschedule on failure. Ephemerality is a feature, not a limitation. If a pod
needs to move, kill it and start a new one.

This is good design advice. It is also not an answer to the actual problem.

## The problem the community's position ignores

Stateful workloads are not a niche. They are the workload:

- **Databases** — PostgreSQL, MySQL, MongoDB. Every company has at least one.
- **In-memory caches** — Redis, Memcached. State that must survive the move.
- **Message brokers** — Kafka, RabbitMQ. Partition leaders and consumer group state.
- **ML training runs** — A 72-hour training job that is 68 hours in cannot be told
  to "just reconnect."
- **Financial transaction processors** — In-flight transactions with microsecond latency
  requirements and zero tolerance for connection reset.

Kubernetes runs all of these workloads today. "Redesign your application to be stateless"
is not an answer when the application is PostgreSQL. It is not an answer when the
application is a training run that costs $40,000 per execution. It is not an answer
at all — it is a deferral.

The container community's resistance was partly principled (stateless-first *is* good
design) and partly path dependence. Containers were born in a world where ephemerality
was a virtue, and the mental model calcified around it. Kubernetes inherited that mental
model. The result is a platform that can run any workload but cannot move the stateful
ones without a service interruption.

## What live VM migration proved — and what it left unsolved

VMware solved this at the VM layer twenty years ago. live VM migration is production-hardened,
battle-tested, and runs in every large enterprise datacenter on earth. The insight it
proved is simple: **live migration is not just possible, it is operationally necessary.**

Node maintenance, cost optimization, failure remediation, workload rebalancing — all of
these require moving running workloads between hosts. At the VM layer, you do this with
live VM migration. At the container layer, you drain the node and accept the downtime. That
asymmetry is not a design choice. It is a gap.

live VM migration operates at Layer 2. A gratuitous ARP updates the switch MAC table and all
traffic follows. It does not solve the Layer 7 problem: if your VM hosts a Kubernetes
cluster and your Kubernetes cluster hosts a pod, live VM migration moves the VM but Kubernetes
still thinks the pod is on the original node. You get VM mobility at the cost of
Kubernetes-level confusion. PodMotion solves the problem at the layer where it actually
lives.

## What PodMotion proved

On 2026-06-12, the M18.5 spike produced this result:

```
sent=576, received=576, errors=0, gaps=[], seq_delta=0
CRIU dump:    94ms
CRIU restore: 200ms (health-check confirmed ESTAB socket)
```

A Python traffic generator with an established TCP connection to an echo server was
checkpointed with CRIU, migrated across network namespaces, and restored. The connection
continued. The application saw nothing. **seq_delta=0** — the TCP sequence numbers were
preserved exactly. No reconnect. No retry. No gap.

This is not "keep the connection alive through reconnect logic." Reconnect-on-failure is
a workaround. `seq_delta=0` is actual migration.

The distinction matters. Reconnect requires the application to handle connection loss.
It requires the peer to handle a new TCP handshake. It requires the load balancer or
proxy to re-establish state. Every layer in the stack must cooperate. `seq_delta=0`
means none of that is required — the connection is not interrupted at all. The peer
does not know the pod moved.

And it is not enough for one container to survive. A pod is not a container — it is a
group of containers sharing a network namespace, a lifecycle, and often shared memory.
Every sidecar, every init container that is still running, every service mesh proxy —
all of them must be checkpointed atomically and restored atomically. A migration that
moves the application container but restarts Envoy is not transparent: Envoy's
connection state is gone, the drain sequence was skipped, and the client *does* notice.
PodMotion checkpoints the entire pod or it does not checkpoint at all.

## Why now

Three things converged to make this possible in 2026 that were not true in 2016:

1. **CRIU maturity.** CRIU 4.x with `--tcp-established`, `--join-ns`, and `--leave-stopped`
   gives us the primitives to freeze, export, and restore a running process including its
   open TCP sockets with exact sequence number preservation.

2. **eBPF at TC/XDP.** The `BPF_PROG_TYPE_SCHED_CLS` and XDP program types give us the
   ability to intercept, rewrite, and redirect network traffic at line rate in the kernel
   data path — without a kernel module, without a patch, on stock Ubuntu 24.04 6.8.

3. **Kubernetes operator maturity.** controller-runtime, NRI, and the CRD ecosystem give
   us the control plane primitives to orchestrate a migration as a first-class Kubernetes
   object with status conditions, rollback, and observability.

None of these existed at production quality simultaneously until recently. The community
was not wrong that live migration was hard — it was wrong that it would stay hard.

## The community will come around

The Kubernetes community came around on persistent volumes — after years of "design
stateless services." It came around on StatefulSets — after years of "use ReplicaSets."
It came around on GPU scheduling — after years of "run ML workloads elsewhere." It will
come around on live migration.

The pattern is consistent: a capability is declared unnecessary until the workloads that
need it become too large to ignore. Stateful workloads running on Kubernetes are already
too large to ignore. They have been for years. The migration path has just been "drain
the node and hope the application recovers."

PodMotion is the answer to the question the community delayed asking.

---

## The one boundary: external traffic routing

PodMotion owns the in-flight connection story completely. CRIU + eBPF preserves every
already-open TCP socket with seq_delta=0 — every client that had a connection before the
migration still has that exact connection after.

There is one thing PodMotion cannot own silently: **where new connections go after the
pod has moved.**

A new connection arrives at a load balancer. The load balancer decides which node to
route it to. If it still sends to the source node — where the pod no longer runs — the
new connection fails. This is not a PodMotion failure. It is a load balancer
configuration problem. But PodMotion is responsible for not letting a migration proceed
until that configuration problem is known to be solved.

**PodMotion's answer is a hard stop, not a silent failure.**

If you try to migrate a pod and the destination node is not registered in your AWS ALB
Target Group, PodMotion blocks the migration before the first CRIU pre-dump with a clear
status condition:

```
TrafficRoutingPreflightPassed = False
Reason: AWSALBNodeNotRegistered
"Destination node ip-10-0-1-45.ec2.internal is not a registered target in
 target group arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/prod-api/abc.
 Register the destination node or set autoRegister=true in MigrationPolicy."
```

No partial attempt. No optimistic "migrate and hope the LB follows." Hard stop, clear
diagnosis, actionable message. This is documented in ADR-0054.

The same logic applies to every external LB type: NLB, Nginx Ingress, Istio, MetalLB,
GCP Cloud Load Balancer, Azure Load Balancer. PodMotion ships a validator for each. If
no validator is registered for a given LB type, the migration is blocked with
`UnknownLoadBalancerType` — requiring the operator to explicitly acknowledge the risk
via `onValidationFailure: Skip` rather than discovering it in production.

This is the only limitation. And it is not a defect — it is the correct behavior for
a system that would rather refuse than silently corrupt.

---

## Key claims (verifiable)

All claims below are backed by reproducible test artifacts in `test/spike/m18.5/`.

| Claim | Evidence |
|-------|----------|
| TCP connection survives migration without application knowledge | `sent=576, received=576, errors=0, gaps=[]` — traffic_gen.py output |
| seq_delta=0 — no sequence number translation required | CRIU TCP_REPAIR preserves snd_nxt/rcv_nxt exactly; confirmed by tcpdump seq analysis |
| 94ms CRIU freeze window | `criu_dump_ms` log field, measured wall-clock ZW-arm to dump-complete |
| Zero RST across migration | tcpdump on source and destination flannel.1; `tcp.flags.reset==1` count: 0 |
| Stock kernel, no patches | Ubuntu 24.04, kernel 6.8, no kernel modules, no kernel patches |
| Drain requirement is load-bearing | `09_negative_test.sh` (ADR-0049): migration without drain produces seq corruption |

---

*This document is the canonical philosophy statement for PodMotion beta materials,
SIG presentations, and the podmotion.io marketing site.*

---

*live VM migration is a registered trademark of VMware, Inc., a subsidiary of Broadcom Inc.
PodMotion is not affiliated with or endorsed by VMware or Broadcom.*
