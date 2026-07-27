# pycriu — Third-Party Attribution and License Notice

This directory (`pycriu/`) contains the **pycriu** package — the official Python
bindings for CRIU (Checkpoint/Restore In Userspace).

- **Upstream project:** CRIU (checkpoint-restore/criu)
- **Upstream location:** `lib/pycriu` within the CRIU source tree
- **Version:** 4.2 (see `version.py`), vendored from CRIU release tag `v4.2`
- **Upstream source:** https://github.com/checkpoint-restore/criu/tree/v4.2/lib/pycriu
- **Copyright:** The CRIU team (criu@lists.linux.dev) and contributors
- **License:** GNU Lesser General Public License, version 2.1 (**LGPL-2.1**)

The full license text is included alongside this notice in
[`LICENSE.LGPL-2.1`](./LICENSE.LGPL-2.1).

Per the CRIU project's top-level `COPYING` file, "any software in the `lib/`
directory ... is licensed under the GNU LESSER GENERAL PUBLIC LICENCE Version
2.1," and CRIU's `lib/pyproject.toml` declares `license = {text = "LGPLv2.1"}`.
pycriu is therefore LGPL-2.1, distinct from the CRIU tool itself (GPL-2.0).

## How PodMotion uses pycriu

pycriu is **not linked into any PodMotion binary**. The node agent (written in Go)
invokes it only as an out-of-process Python module: a `python3` subprocess is
launched with `PYTHONPATH=/usr/lib/python3/dist-packages`, which imports pycriu to
decode/inspect/patch CRIU checkpoint images during the migration checkpoint and
restore paths (see `internal/agent/server/`). This subprocess boundary is analogous
to — and consistent with — the way the CRIU binary itself is used only as an
external subprocess (ADR-0002).

## Redistribution

pycriu as vendored here is **unmodified** relative to CRIU release `v4.2`
(`lib/pycriu`); the `*_pb2.py` files are the protobuf bindings generated from
CRIU's `.proto` definitions. This package is redistributed under LGPL-2.1, which
permits redistribution provided the license text and this attribution are
preserved. Downstream redistributors must keep this notice and `LICENSE.LGPL-2.1`
intact, and may obtain the corresponding source for the library from the upstream
location above. Modifications to this vendored copy must be made available under
LGPL-2.1.

This notice ships inside the PodMotion agent container image because the entire
`pycriu/` directory is copied into the image (see `images/agent/Dockerfile`),
satisfying the LGPL-2.1 obligation to accompany the distributed library with its
license and attribution.
