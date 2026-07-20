# PodMotion.io kubeadm-ubuntu node AMI — Packer build template
#
# Usage (run from the repo root):
#   cd images/capi/packer
#   packer init kubeadm-ubuntu.pkr.hcl
#   packer build -var-file=kubeadm-ubuntu.pkrvars.hcl kubeadm-ubuntu.pkr.hcl
#
# Produces a golden AMI for the EC2 kubeadm proving ground
# (terraform/kubeadm-ec2/), based on the SAME official Ubuntu 24.04 base
# image that module's data "aws_ami" "ubuntu_2404" block already resolves
# (see main.tf) — so this AMI is a drop-in replacement for that base image.
# Unlike the EKS-optimized base AMI the eks-node.pkr.hcl build starts from,
# plain Ubuntu 24.04 does NOT come with containerd/kubeadm/kubelet/kubectl
# preinstalled, so this template runs an extra role (k8s-prereqs) before
# the existing podmotion-node role to install that layer — see
# ../ansible/playbook-kubeadm-ubuntu.yml.
#
# Bakes in PodMotion's node-agent, NRI plugin, and kernel/CRIU
# prerequisites (../ansible/roles/podmotion-node/), so future
# terraform/kubeadm-ec2 launches start from a fully-provisioned node
# instead of the slow from-scratch bootstrap-over-SSH path.

packer {
  required_version = ">= 1.10.0"

  required_plugins {
    amazon = {
      version = ">= 1.2.8"
      source  = "github.com/hashicorp/amazon"
    }
    ansible = {
      version = ">= 1.1.1"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

## -----------------------------------------------------------------------------
## Variables — values supplied via -var-file (see kubeadm-ubuntu.pkrvars.hcl)
## -----------------------------------------------------------------------------

variable "ami_filter_name" {
  type        = string
  description = "Name filter for the base Ubuntu 24.04 AMI to build on top of — must match terraform/kubeadm-ec2/main.tf's data \"aws_ami\" \"ubuntu_2404\" block so this AMI is a drop-in replacement."
}

variable "ami_filter_owner" {
  type        = string
  description = "AWS account ID that owns the base AMI (099720109477 = Canonical, official Ubuntu account)."
}

variable "instance_type" {
  type        = string
  default     = "t3.large"
  description = "EC2 instance type used to build the image — matches terraform/kubeadm-ec2/variables.tf's instance_type default so the build environment matches the eventual runtime environment."
}

variable "region" {
  type        = string
  description = "AWS region to build in (and to source the base AMI from) — must match the region terraform/kubeadm-ec2 actually launches nodes in, since the produced AMI only needs to exist there."
}

variable "subnet_id" {
  type        = string
  default     = ""
  description = "Subnet for the build instance. Empty string = let Packer pick the default VPC's default subnet."
}

variable "associate_public_ip" {
  type        = bool
  default     = true
  description = "Whether the build instance gets a public IP (needed for internet access to install packages unless the subnet has a NAT gateway)."
}

variable "iam_instance_profile" {
  type        = string
  default     = ""
  description = "Instance profile attached to the build instance. Not required for this build — no S3 fetch is involved, artifacts are staged from the local machine running packer build."
}

variable "ami_name_prefix" {
  type        = string
  description = "Prefix for the produced AMI's name."
}

variable "podmotion_version" {
  type        = string
  description = "PodMotion release version this image is built for — embedded in the AMI name and tags."
}

variable "ami_regions" {
  type        = list(string)
  default     = []
  description = "Additional regions to copy the finished AMI to. The build region is always included."
}

variable "encrypt_boot" {
  type        = bool
  default     = false
  description = "Whether to encrypt the root EBS volume of the produced AMI."
}

variable "kubernetes_version" {
  type        = string
  description = "Kubernetes minor version this image installs via kubeadm/kubelet/kubectl (e.g. \"1.32\") — passed through to the k8s-prereqs role as kubernetes_minor_version and used as an informational tag."
}

variable "root_volume_gb" {
  type        = number
  default     = 40
  description = "Root EBS volume size in GB — matches terraform/kubeadm-ec2/variables.tf's root_volume_gb default."
}

## -----------------------------------------------------------------------------
## Local build-artifact staging — NO S3. This project has no artifact bucket,
## so (unlike eks-node.pkr.hcl's podmotion_agent_s3_uri/podmotion_preflight_s3_uri)
## these are plain repo-relative filesystem paths on the machine running
## `packer build`, copied into ../ansible/roles/podmotion-node/files/ by a
## shell-local provisioner (cp, not aws s3 cp) before the ansible provisioner
## runs, and removed again afterward — same before/after shell-local pattern
## eks-node.pkr.hcl uses, just swapping the source.
## -----------------------------------------------------------------------------

variable "podmotion_agent_local_path" {
  type        = string
  default     = "../../../bin/podmotion-agent-amd64"
  description = "Repo-relative path (from images/capi/packer/) to the pre-compiled podmotion-agent binary (linux/amd64) — produced by `make build-linux` at the repo root."
}

variable "podmotion_preflight_local_path" {
  type        = string
  default     = "../../../scripts/podmotion-preflight-amazon.sh"
  description = "Repo-relative path (from images/capi/packer/) to the podmotion-preflight-amazon.sh script."
}

variable "bpf_zero_window_bpfel_local_path" {
  type        = string
  default     = "../../../bpf/zero_window_bpfel.o"
  description = "Repo-relative path (from images/capi/packer/) to the compiled zero-window-hold eBPF object (little-endian)."
}

variable "bpf_zero_window_bpfeb_local_path" {
  type        = string
  default     = "../../../bpf/zero_window_bpfeb.o"
  description = "Repo-relative path (from images/capi/packer/) to the compiled zero-window-hold eBPF object (big-endian)."
}

variable "ansible_extra_vars" {
  type        = map(string)
  default     = {}
  description = "Extra vars passed through to both Ansible roles (e.g. podmotion_version for podmotion-node, kubernetes_minor_version/kubernetes_package_version for k8s-prereqs)."
}

variable "ami_tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to the produced AMI and its snapshots."
}

## -----------------------------------------------------------------------------
## Base AMI lookup — same filter/owner as terraform/kubeadm-ec2/main.tf's
## data "aws_ami" "ubuntu_2404" block, so this build starts from the exact
## same base image that module would otherwise launch directly.
## -----------------------------------------------------------------------------

data "amazon-ami" "ubuntu_2404" {
  filters = {
    name                = var.ami_filter_name
    virtualization-type = "hvm"
  }
  owners      = [var.ami_filter_owner]
  most_recent = true
  region      = var.region
}

## -----------------------------------------------------------------------------
## Build source
## -----------------------------------------------------------------------------

locals {
  # Packer HCL has no built-in strftime; the amazon-ebs builder timestamps the
  # AMI name itself if left unset, but we want our own scheme to match the
  # kubeadm-ubuntu.pkrvars.hcl header comment.
  build_timestamp = formatdate("YYYYMMDDhhmmss", timestamp())
  ami_name        = "${var.ami_name_prefix}-${var.podmotion_version}-${local.build_timestamp}"

  common_tags = merge(var.ami_tags, {
    Name                            = local.ami_name
    "podmotion.io/kubernetes-version" = var.kubernetes_version
    "podmotion.io/base-ami"         = data.amazon-ami.ubuntu_2404.id
  })
}

source "amazon-ebs" "podmotion_io_kubeadm_ubuntu" {
  ami_name      = local.ami_name
  ami_regions   = distinct(concat([var.region], var.ami_regions))
  encrypt_boot  = var.encrypt_boot
  instance_type = var.instance_type
  region        = var.region
  source_ami    = data.amazon-ami.ubuntu_2404.id
  ssh_username  = "ubuntu"

  subnet_id                   = var.subnet_id != "" ? var.subnet_id : null
  associate_public_ip_address = var.associate_public_ip
  iam_instance_profile        = var.iam_instance_profile != "" ? var.iam_instance_profile : null

  tags     = local.common_tags
  run_tags = merge(local.common_tags, { Name = "packer-builder-${local.ami_name}" })

  launch_block_device_mappings {
    device_name = "/dev/sda1"
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    delete_on_termination = true
  }
}

## -----------------------------------------------------------------------------
## Build
## -----------------------------------------------------------------------------

build {
  name    = "podmotion-io-kubeadm-ubuntu"
  sources = ["source.amazon-ebs.podmotion_io_kubeadm_ubuntu"]

  # Stage the pre-compiled agent binary, preflight script, and BPF objects
  # from the LOCAL repo checkout (the machine running `packer build`) into
  # ../ansible/roles/podmotion-node/files/ — the ansible provisioner below
  # runs ansible-playbook locally over SSH, so the podmotion-node role's
  # `copy` tasks need these files to already exist there before that step
  # runs. No S3 bucket exists for this project; plain cp from the repo tree.
  provisioner "shell-local" {
    # Packer's shell-local runs inline scripts via /bin/sh by default, which
    # is dash on this build host — dash's builtin `set` has no -o pipefail.
    # Force bash explicitly rather than dropping pipefail.
    inline_shebang = "/bin/bash -e"
    inline = [
      "set -euo pipefail",
      "cp '${var.podmotion_agent_local_path}' ../ansible/roles/podmotion-node/files/podmotion-agent",
      "cp '${var.podmotion_preflight_local_path}' ../ansible/roles/podmotion-node/files/podmotion-preflight-amazon.sh",
      "cp '${var.bpf_zero_window_bpfel_local_path}' ../ansible/roles/podmotion-node/files/zero_window_bpfel.o",
      "cp '${var.bpf_zero_window_bpfeb_local_path}' ../ansible/roles/podmotion-node/files/zero_window_bpfeb.o",
      "chmod +x ../ansible/roles/podmotion-node/files/podmotion-agent",
      "chmod +x ../ansible/roles/podmotion-node/files/podmotion-preflight-amazon.sh",
    ]
  }

  provisioner "ansible" {
    playbook_file = "../ansible/playbook-kubeadm-ubuntu.yml"
    user          = "ubuntu"
    extra_arguments = [
      "--extra-vars",
      jsonencode(merge(var.ansible_extra_vars, {
        kubernetes_minor_version = var.kubernetes_version
      })),
    ]
  }

  # Clean up the staged files from the local ansible files/ dir so they
  # don't get committed to git or linger stale between builds — mirrors
  # eks-node.pkr.hcl's cleanup step exactly.
  provisioner "shell-local" {
    inline = [
      "rm -f ../ansible/roles/podmotion-node/files/podmotion-agent",
      "rm -f ../ansible/roles/podmotion-node/files/podmotion-preflight-amazon.sh",
      "rm -f ../ansible/roles/podmotion-node/files/zero_window_bpfel.o",
      "rm -f ../ansible/roles/podmotion-node/files/zero_window_bpfeb.o",
    ]
  }

  post-processor "manifest" {
    output     = "manifest-kubeadm-ubuntu.json"
    strip_path = true
    custom_data = {
      podmotion_version  = var.podmotion_version
      kubernetes_version = var.kubernetes_version
      base_ami           = data.amazon-ami.ubuntu_2404.id
    }
  }
}
