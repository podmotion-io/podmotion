# Packer variables for the PodMotion.io kubeadm-ubuntu golden AMI
# Usage:
#   packer build -var-file=images/capi/packer/kubeadm-ubuntu.pkrvars.hcl \
#                images/capi/packer/kubeadm-ubuntu.pkr.hcl
#
# Produces a golden AMI for the EC2 kubeadm proving ground
# (terraform/kubeadm-ec2/) — a drop-in replacement for that module's
# data "aws_ami" "ubuntu_2404" base image, with containerd, kubeadm/kubelet/
# kubectl, and PodMotion (agent + NRI + CRIU prerequisites) already baked in.
#
# Requires:
#   - packer >= 1.10
#   - amazon + ansible plugins: packer init .
#   - AWS credentials with ec2:CreateImage, ec2:RunInstances, etc.
#   - `make build-linux` already run at the repo root (stages bin/podmotion-agent-amd64)

# ---- Base AMI ------------------------------------------------------------------
# Same filter/owner as terraform/kubeadm-ec2/main.tf's data "aws_ami" "ubuntu_2404"
# block — Canonical's official Ubuntu 24.04 (Noble) account.
ami_filter_name  = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
ami_filter_owner = "099720109477" # Canonical

# ---- Build instance --------------------------------------------------------------
# t3.large + us-east-2 match terraform/kubeadm-ec2/variables.tf's instance_type
# and aws_region defaults — the AMI needs to exist in the same region the EC2
# instances actually launch in.
instance_type       = "t3.large"
region              = "us-east-2"
root_volume_gb      = 40
subnet_id           = "" # leave empty to use default VPC
associate_public_ip = true
iam_instance_profile = "" # not required — no S3 fetch in this build

# ---- Output AMI --------------------------------------------------------------
ami_name_prefix   = "podmotion-io-kubeadm-ubuntu"
# Final name: podmotion-io-kubeadm-ubuntu-v0.1.0-YYYYMMDDHHMMSS
podmotion_version = "v0.1.0"
ami_regions       = ["us-east-2"]
encrypt_boot      = false

# ---- Kubernetes version to install (kubeadm/kubelet/kubectl, pkgs.k8s.io) --------
kubernetes_version = "1.32"

# ---- Local build-artifact paths (repo-relative, from images/capi/packer/) --------
# No S3 bucket exists for this project — artifacts are staged straight from the
# local repo checkout. `make build-linux` (repo root) must be run first.
podmotion_agent_local_path       = "../../../bin/podmotion-agent-amd64"
podmotion_preflight_local_path   = "../../../scripts/podmotion-preflight-amazon.sh"
bpf_zero_window_bpfel_local_path = "../../../bpf/zero_window_bpfel.o"
bpf_zero_window_bpfeb_local_path = "../../../bpf/zero_window_bpfeb.o"

# ---- Ansible role variables -------------------------------------------------
# Passed to ansible-playbook as --extra-vars (merged with
# kubernetes_minor_version=var.kubernetes_version by the template itself).
ansible_extra_vars = {
  podmotion_version       = "v0.1.0"
  selinux_module_install  = "false" # Ubuntu — no SELinux, role skips this via ansible_os_family
}

# ---- Tags (podmotion.io/* namespace — this AMI is meant to eventually be a
# public-facing artifact, so it uses the podmotion.io tag namespace rather
# than the internal podmotion/* namespace al2023.pkrvars.hcl uses) -----------
ami_tags = {
  "podmotion.io/version"            = "v0.1.0"
  "podmotion.io/distro"             = "ubuntu-24.04"
  "podmotion.io/kubernetes-version" = "1.32"
  "podmotion.io/nri-ready"          = "true"
  "podmotion.io/criu-version"       = "4.2-src-3c7d4fa0" # built from source, pinned commit (apt has no criu package on noble)
  "podmotion.io/mem-soft-dirty"     = "true"
  "podmotion.io/target"             = "kubeadm-ec2"
}
