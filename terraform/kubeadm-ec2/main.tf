# kubeadm-ec2 — a minimal, self-managed 2-node kubeadm cluster on plain EC2.
#
# This is the "EC2 kubeadm" leg of the KVM-matrix -> EC2 -> EKS -> public-push
# roadmap: prove PodMotion works on real AWS instances before layering EKS's
# managed control plane on top. Deliberately small — 1 control-plane + 1 worker,
# no HA, no autoscaling. This is a proving ground, not production infrastructure.
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
data "aws_ami" "ubuntu_2404" {
  most_recent = true
  owners      = ["868558231918"] # this account — self-published golden AMI

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
    Name = "${local.name_prefix}-worker"
    Role = "worker"
  }
}

# ── Local operator tooling ───────────────────────────────────────────────
# Written on every apply so this workstation can immediately SSH into both
# nodes (to run kubeadm bootstrap, repair failures, deploy PodMotion, etc.)
# without any manual key/IP wrangling — same hosts.env + ssh.sh pattern
# already used for the KVM substrate (/home/chad/podmotion-kvm/), so the
# same muscle memory and scripts work against either substrate.

resource "local_file" "hosts_env" {
  filename = "${path.module}/hosts.env"
  content  = <<-EOT
    # Generated by terraform apply — do not edit by hand, re-apply instead.
    CP1=${aws_instance.control_plane.public_ip}
    W1=${aws_instance.worker.public_ip}
  EOT
}

resource "local_file" "ssh_helper" {
  filename        = "${path.module}/ssh.sh"
  file_permission = "0755"
  content         = <<-EOT
    #!/usr/bin/env bash
    # ssh.sh <ip> "<cmd>" — same calling convention as the KVM substrate's
    # own /home/chad/podmotion-kvm/ssh.sh. Usage: bash ssh.sh $CP1 "sudo systemctl status kubelet"
    set -euo pipefail
    ip="$1"; shift
    exec ssh -i "$(dirname "$0")/${local.name_prefix}-ssh-key.pem" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o LogLevel=ERROR \
      "ubuntu@$ip" "$@"
  EOT
}
