# kubeadm-ec2-quickstart — a minimal, self-managed kubeadm cluster on plain EC2.
#
# This is a standalone fork of terraform/kubeadm-ec2/, parameterized for
# general use and with its OWN Terraform state (never touches
# terraform/kubeadm-ec2/'s .terraform/terraform.tfstate/hosts.env/ssh keys).
# Same "prove PodMotion on real AWS instances" purpose — 1 control-plane +
# N workers (default 2), no HA, no autoscaling. This is a proving ground /
# quickstart, not production infrastructure.
#
# This module intentionally stops at "reachable boxes" (Terraform does not
# run kubeadm) — see bootstrap.sh in this directory for the kubeadm
# init/join + Longhorn + PodMotion install automation that runs after
# `terraform apply`.
#
# SSH is locked to the caller's own public IP at apply-time (data.http.my_public_ip),
# never opened to 0.0.0.0/0 — matches this project's standing security posture.

data "http" "my_public_ip" {
  url = "https://checkip.amazonaws.com"
}

locals {
  ssh_allowed_cidr = coalesce(
    var.ssh_allowed_cidr_override,
    "${trimspace(data.http.my_public_ip.response_body)}/32"
  )
  name_prefix = var.cluster_name
}

# ── SSH key ───────────────────────────────────────────────────────────────
# Generated fresh per-apply and written locally (0600) rather than requiring
# a pre-existing AWS key pair — keeps this module self-contained.

resource "tls_private_key" "ssh" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "this" {
  key_name   = "${local.name_prefix}-key"
  public_key = tls_private_key.ssh.public_key_openssh
}

resource "local_sensitive_file" "ssh_private_key" {
  filename        = "${path.module}/${local.name_prefix}-ssh-key.pem"
  content         = tls_private_key.ssh.private_key_openssh
  file_permission = "0600"
}

# ── Networking (dedicated, minimal — one public subnet per AZ, 2 AZs) ───────

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-igw" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ── Security group ───────────────────────────────────────────────────────
# SSH: caller IP only. Kubernetes control-plane/kubelet/etcd/NodePort ports
# and CNI overlay ports (VXLAN 8472 for Flannel/Calico, Geneve 6081 for
# Cilium) are open between cluster members only (self-referencing SG), never
# to the internet — mirrors the KVM substrate's own NAT-isolated posture.

resource "aws_security_group" "cluster" {
  name        = "${local.name_prefix}-sg"
  description = "kubeadm proving-ground cluster: SSH from caller IP, k8s+CNI traffic between nodes only"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-sg" }
}

resource "aws_security_group_rule" "ssh_from_caller" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [local.ssh_allowed_cidr]
  security_group_id = aws_security_group.cluster.id
  description       = "SSH from the apply-time caller IP only"
}

resource "aws_security_group_rule" "k8s_api_from_caller" {
  type              = "ingress"
  from_port         = 6443
  to_port           = 6443
  protocol          = "tcp"
  cidr_blocks       = [local.ssh_allowed_cidr]
  security_group_id = aws_security_group.cluster.id
  description       = "kube-apiserver from the apply-time caller IP only (kubectl access)"
}

resource "aws_security_group_rule" "intra_cluster_all_tcp" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.cluster.id
  description       = "All TCP between cluster members (etcd, kubelet, NodePort, CRIU/checkpoint transfer, CNI control-plane)"
}

resource "aws_security_group_rule" "intra_cluster_all_udp" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "udp"
  self              = true
  security_group_id = aws_security_group.cluster.id
  description       = "All UDP between cluster members (VXLAN 8472 / Geneve 6081 CNI overlay, whichever CNI is installed)"
}

resource "aws_security_group_rule" "demo_web_from_caller" {
  type              = "ingress"
  from_port         = var.demo_web_node_port
  to_port           = var.demo_web_node_port
  protocol          = "tcp"
  cidr_blocks       = [local.ssh_allowed_cidr]
  security_group_id = aws_security_group.cluster.id
  description       = "podmotion-demo web UI (NodePort) from the apply-time caller IP only"
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cluster.id
  description       = "Unrestricted egress (package installs, image pulls, kubeadm/CNI manifests)"
}

# ── AMI: our own golden "podmotion-io-kubeadm-ubuntu" image ─────────────────
# Built via images/capi/packer/kubeadm-ubuntu.pkr.hcl — Ubuntu 24.04 base with
# containerd, kubeadm/kubelet/kubectl, CRIU 4.2 (built from source with
# libnftables support), the /usr/local/bin/ctr symlink, and PodMotion's
# agent/NRI/CRIU prerequisites already baked in. Data source block kept named
# "ubuntu_2404" so the resource references below don't need to change.
#
# owners is parameterized (var.ami_owner_account_id) rather than hardcoded —
# this AMI is privately owned by the PodMotion maintainer's account and is
# NOT publicly shared. See variables.tf's ami_owner_account_id description
# for what to do if you're not that account (get access, or build your own
# copy via the Packer template — publishing the AMI itself is out of scope
# for this module).
data "aws_ami" "ubuntu_2404" {
  most_recent = true
  owners      = [var.ami_owner_account_id]

  filter {
    name   = "name"
    values = ["podmotion-io-kubeadm-ubuntu-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── Nodes: 1 control-plane + 1 worker ────────────────────────────────────
# Deliberately NOT auto-running kubeadm init/join here — this module's job is
# to hand you two reachable Ubuntu 24.04 boxes with the right networking and
# SSH access; the actual kubeadm bootstrap is a separate, explicit step (same
# "prove infra first, then bootstrap" separation the KVM substrate's own
# hack/kvm-cluster.sh uses). See outputs.tf for the SSH commands.

resource "aws_instance" "control_plane" {
  ami                    = data.aws_ami.ubuntu_2404.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.this.key_name
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.cluster.id]

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  tags = {
    Name = "${local.name_prefix}-control-plane"
    Role = "control-plane"
  }
}

resource "aws_instance" "worker" {
  count = var.worker_count

  ami                    = data.aws_ami.ubuntu_2404.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.this.key_name
  subnet_id              = aws_subnet.public[1].id
  vpc_security_group_ids = [aws_security_group.cluster.id]

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  tags = {
    Name = "${local.name_prefix}-worker-${count.index + 1}"
    Role = "worker"
  }
}

# ── Longhorn backend storage ──────────────────────────────────────────────
# One dedicated EBS volume per node (control-plane included, matching the KVM
# substrate's 3-disk/3-replica topology — hack/kvm-cluster.sh's
# provision-longhorn attaches to pm-cp1+pm-w1+pm-w2 and the longhorn-migratable
# StorageClass there is numberOfReplicas=3). Nitro instances (t3.*) attach
# extra EBS volumes as NVMe devices — the in-guest device name is NOT
# predictable ahead of time (no /dev/sdf-style naming on Nitro), so whatever
# provisions the node must discover it at runtime (e.g. diff `lsblk` before/
# after, or match by exact size) rather than assume a fixed path.
# gp3, 30Gi — sized down from the KVM setup's 250G qcow2 (near-free local
# disk) since AWS EBS is billed per GB-month; adjust if a larger proof dataset
# is needed.

resource "aws_ebs_volume" "longhorn_control_plane" {
  availability_zone = aws_instance.control_plane.availability_zone
  size              = var.longhorn_disk_gb
  type              = "gp3"

  tags = { Name = "${local.name_prefix}-longhorn-control-plane" }
}

resource "aws_volume_attachment" "longhorn_control_plane" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.longhorn_control_plane.id
  instance_id = aws_instance.control_plane.id
}

resource "aws_ebs_volume" "longhorn_worker" {
  count = var.worker_count

  availability_zone = aws_instance.worker[count.index].availability_zone
  size              = var.longhorn_disk_gb
  type              = "gp3"

  tags = { Name = "${local.name_prefix}-longhorn-worker-${count.index + 1}" }
}

resource "aws_volume_attachment" "longhorn_worker" {
  count = var.worker_count

  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.longhorn_worker[count.index].id
  instance_id = aws_instance.worker[count.index].id
}

# ── Local operator tooling ───────────────────────────────────────────────
# Written on every apply so this workstation can immediately SSH into both
# nodes (to run kubeadm bootstrap, repair failures, deploy PodMotion, etc.)
# without any manual key/IP wrangling — same hosts.env + ssh.sh pattern
# already used for the KVM substrate (the KVM quickstart's KVM_DIR), so the
# same muscle memory and scripts work against either substrate.

resource "local_file" "hosts_env" {
  filename = "${path.module}/hosts.env"
  content  = <<-EOT
    # Generated by terraform apply — do not edit by hand, re-apply instead.
    CP1=${aws_instance.control_plane.public_ip}
    %{for i, w in aws_instance.worker~}
    W${i + 1}=${w.public_ip}
    %{endfor~}
  EOT
}

resource "local_file" "ssh_helper" {
  filename        = "${path.module}/ssh.sh"
  file_permission = "0755"
  content         = <<-EOT
    #!/usr/bin/env bash
    # ssh.sh <ip> "<cmd>" — same calling convention as the KVM substrate's
    # own ssh.sh helper (path to your ssh.sh script). Usage: bash ssh.sh $CP1 "sudo systemctl status kubelet"
    set -euo pipefail
    ip="$1"; shift
    exec ssh -i "$(dirname "$0")/${local.name_prefix}-ssh-key.pem" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o LogLevel=ERROR \
      "ubuntu@$ip" "$@"
  EOT
}

# ── Automatic bootstrap ───────────────────────────────────────────────────
# Chad's explicit direction (2026-07-21): `terraform apply` should bring the
# whole stack up by itself, not stop at bare boxes with a separate manual
# step. This runs bootstrap.sh (kubeadm init/join + Longhorn + PodMotion
# operator + podmotion-demo + test workloads) automatically once every node
# is up and both EBS volumes are attached.
#
# Implemented as a null_resource local-exec (runs bootstrap.sh from THIS
# workstation, which already has the demo-repo checkout, docker, helm, etc. —
# not a remote-exec on the instances themselves) so it reuses the exact same
# script already proven live on the previous manual runs, rather than
# duplicating that logic inline in HCL.
#
# triggers keyed on every node's instance ID: replacing any node (a fresh
# apply after a destroy, or a future change that forces recreation) reruns
# bootstrap automatically. It does NOT rerun on a plain re-apply against
# already-bootstrapped, unchanged instances — bootstrap.sh's own steps are
# themselves idempotent (kubeadm/helm/kubectl apply), so a manual re-run is
# still safe if ever needed, but this resource only fires once per node
# generation by default.
#
# Waits for SSH on all 3 nodes first (fresh instances can take a minute-plus
# to finish booting before sshd is reachable) rather than assuming
# `aws_instance` "created" means "reachable".

resource "null_resource" "bootstrap" {
  triggers = {
    control_plane_id = aws_instance.control_plane.id
    worker_ids       = join(",", aws_instance.worker[*].id)
    cp_volume_attach = aws_volume_attachment.longhorn_control_plane.id
  }

  depends_on = [
    aws_volume_attachment.longhorn_control_plane,
    aws_volume_attachment.longhorn_worker,
    local_file.hosts_env,
    local_sensitive_file.ssh_private_key,
  ]

  provisioner "local-exec" {
    working_dir = path.module
    interpreter = ["/usr/bin/env", "bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      KEY="./${local.name_prefix}-ssh-key.pem"
      NODES="${aws_instance.control_plane.public_ip} ${join(" ", aws_instance.worker[*].public_ip)}"

      echo "==> Waiting for SSH on all nodes before running bootstrap.sh..."
      for ip in $NODES; do
        for i in $(seq 1 60); do
          if ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o ConnectTimeout=5 -o BatchMode=yes ubuntu@"$ip" true 2>/dev/null; then
            echo "    $ip reachable"
            break
          fi
          if [ "$i" -eq 60 ]; then
            echo "ERROR: $ip did not become SSH-reachable after 5 minutes" >&2
            exit 1
          fi
          sleep 5
        done
      done

      echo "==> Running bootstrap.sh..."
      ./bootstrap.sh
    EOT
  }
}
