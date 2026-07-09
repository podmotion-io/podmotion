# PodMotion Roadmap

This file is retained as a stable, low-churn entry point into PodMotion's planning
docs. It is intentionally short — it does not duplicate milestone or sprint detail
that lives elsewhere and changes far more often than this pointer should.

## North Star

PodMotion exists to deliver **complete bilateral transparency** for live pod
migration across nodes within a single cluster: **ALL containers** in the pod are
unaware they moved (every app container, every sidecar, every log shipper), **ALL
clients** with open TCP connections are unaware the pod moved, and `seq_delta=0` —
exact TCP sequence number preservation. No RST, no reconnect, no retry, no
client-side reconnect logic required.

## Where the authoritative detail lives

- **Current sprint plan (M22–M30):** [`docs/CURRENT-POSITION.md`](./CURRENT-POSITION.md)
- **Milestone ledger (M1–M21):** [`docs/MILESTONES.md`](./MILESTONES.md)
- **Live "where are we right now" state:** see [`docs/CURRENT-POSITION.md`](./CURRENT-POSITION.md) above — the
  project's tracked, published state tracker (internal resumption machinery is not published)

This document is not updated milestone-by-milestone; update the files above instead.
