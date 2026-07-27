# kubeadm-ec2-quickstart

A standalone, parameterized fork of `terraform/kubeadm-ec2/` for standing up
a real kubeadm cluster on plain EC2 — fully automatic: `terraform apply`
brings up the instances AND runs `bootstrap.sh` for you (kubeadm init/join,
Longhorn, the PodMotion operator, the `podmotion-demo` app, and the
`test/e2e/fixtures/{redis,postgres,nginx}` test workloads), via a
`null_resource` provisioner that waits for SSH and then invokes it. No
separate manual step required.

This module has its **own Terraform state**, own generated SSH key, and own
`hosts.env`/`ssh.sh` helpers — it never touches `terraform/kubeadm-ec2/`'s
`.terraform/`, `terraform.tfstate`, or generated files. Safe to apply
alongside that module's own live-applied resources in the same AWS
account/region (the `cluster_name` default is `podmotion-kubeadm-quickstart`,
distinct from that module's `podmotion-kubeadm`, specifically so the two
don't collide on globally-unique-per-account names like the SSH key pair).

## Quickstart

```bash
cd terraform/kubeadm-ec2-quickstart
terraform init
terraform apply        # creates real, BILLABLE AWS resources — review the plan first
```

That's it — a single `apply` creates the instances, waits for them to be
SSH-reachable, then runs `bootstrap.sh` automatically (kubeadm init/join,
Longhorn, PodMotion operator, `podmotion-demo`, and the test workloads). The
full run takes roughly 10-15 minutes; Terraform's own progress output shows
`bootstrap.sh`'s log lines prefixed with `null_resource.bootstrap
(local-exec):` while it works. When `apply` finishes, the outputs (demo URL,
kubeconfig path, etc.) are ready to use immediately — no separate step needed.

`bootstrap.sh` reads everything it needs (node IPs, the SSH key path, the pod
CIDR) from `terraform output -json`, so no manual IP-wrangling happens either
way. It requires a sibling checkout of the separate `podmotion-demo`
**application** repo (web + api source + Dockerfiles — not the
`charts/podmotion-demo` Helm chart, which already lives in this repo) at
`../../../podmotion-demo` next to this repo's root, matching
`hack/quickstart-kind.sh`'s own convention.

If you ever need to run it by hand instead (e.g. after a manual fix), it's
still a normal script: `./bootstrap.sh [--demo-repo PATH] [--skip-demo]
[--skip-workloads]` — run `./bootstrap.sh --help` for all options. Re-applying
against an unchanged, already-bootstrapped cluster does NOT re-run it (the
provisioner is keyed to instance IDs); replacing a node (e.g. after a
`destroy`/fresh `apply`) does.

### What you get

- 1 control-plane + N worker EC2 instances (default N=2), kubeadm-bootstrapped
  with Flannel CNI, `kubeconfig` exported locally to this directory.
- Longhorn installed, with a dedicated EBS volume per node formatted and
  mounted, plus an RWX `longhorn-migratable` StorageClass for live migration.
- The PodMotion operator + agent DaemonSet, mTLS dev certs, and CRDs.
- The `podmotion-demo` app (web + api), unless `--skip-demo` is passed.
- The `test/e2e/fixtures/{redis,postgres,nginx}` workloads in namespace
  `pm-e2e`, unless `--skip-workloads` is passed.

## AMI ownership — read this before applying

The golden node AMI (`podmotion-io-kubeadm-ubuntu-*` — Ubuntu 24.04 with
containerd, kubeadm/kubelet/kubectl, and CRIU pre-baked via
`images/capi/packer/kubeadm-ubuntu.pkr.hcl` + the `k8s-prereqs`/
`podmotion-node` Ansible roles) is **privately owned by the PodMotion
maintainer's own AWS account** (`868558231918`, the `ami_owner_account_id`
variable's default). It is not publicly shared.

If you are not that account, `terraform apply` will fail at the
`data "aws_ami" "ubuntu_2404"` lookup (no matching AMI visible to you). You
have two options:

1. **Get access to the existing AMI** — have the owner share/copy it to your
   account, then set `ami_owner_account_id` to the account that now owns
   your copy.
2. **Build your own copy** — run the existing Packer template yourself:
   ```bash
   cd images/capi/packer
   packer init kubeadm-ubuntu.pkr.hcl
   packer build -var-file=kubeadm-ubuntu.pkrvars.hcl kubeadm-ubuntu.pkr.hcl
   ```
   then set `ami_owner_account_id` to your own AWS account ID.

Publishing/sharing the AMI itself is out of scope for this module — see
`variables.tf`'s `ami_owner_account_id` description for the full detail.

## Cost and teardown

This creates real, billable AWS resources: EC2 instances (default
`t3.large` x 3), EBS volumes (root + a dedicated Longhorn volume per node),
and a VPC/IGW/route table/security group (free, but the instances and
volumes are not). Nothing here is free-tier-eligible at the default sizing.

**Tear it down when you're done:**

```bash
cd terraform/kubeadm-ec2-quickstart
terraform destroy
```

Leaving the cluster running past when you need it is the single most common
way to rack up an unexpected AWS bill from this module.

## Verification status

Live-verified end to end, 2026-07-21: `terraform apply` alone (with the
`null_resource.bootstrap` auto-provisioner) brought up 3 real EC2 nodes,
Longhorn, the operator + agents, `podmotion-demo`, and the `pm-e2e` test
workloads with no manual step — confirmed via `kubectl get pods -A` (all
Running) and a real `curl` against the demo web UI (HTTP 200, real content).
A `PodMigration` reaching `Complete` on this same automation was separately
proven in an earlier manual-bootstrap run before the auto-apply wiring was
added; the underlying install recipe is unchanged, only its trigger moved
from a manual `./bootstrap.sh` call into the `apply` itself.
