# PodMotion EKS node AMI — Packer build template
#
# Usage (run from the repo root):
#   cd images/capi/packer
#   packer init eks-node.pkr.hcl
#   packer build -var-file=al2023.pkrvars.hcl eks-node.pkr.hcl
#
# Produces a custom AMI, based on the official AWS EKS-optimized node image,
# with PodMotion's node-agent, NRI plugin, and kernel/CRIU prerequisites
# baked in (see ../ansible/roles/podmotion-node/). Intended for use with a
# custom EKS managed-node-group launch template — see terraform/eks-cluster/.
#
# KNOWN ISSUE: images/capi/ansible/roles/podmotion-node/files/ is missing the
# compiled zero_window_bpfel.o / zero_window_bpfeb.o eBPF objects the role's
# task list expects (bpf/ in the main repo needs to be built and copied in
# before this produces a fully-working image) — build will still succeed,
# but the resulting node won't have the zero-window-hold datapath until
# that's added.

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
## Variables — values supplied via -var-file (see al2023.pkrvars.hcl)
## -----------------------------------------------------------------------------

variable "ami_filter_name" {
  type        = string
  description = "Name filter for the base EKS-optimized AMI to build on top of."
}

variable "ami_filter_owner" {
  type        = string
  description = "AWS account ID that owns the base AMI (602401143452 for official EKS-optimized images)."
}

variable "instance_type" {
  type        = string
  default     = "m5.xlarge"
  description = "EC2 instance type used to build the image."
}

variable "region" {
  type        = string
  description = "AWS region to build in (and to source the base AMI from)."
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
  description = "Instance profile attached to the build instance (needs at least S3 read access to fetch the agent binary)."
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
  description = "EKS/Kubernetes minor version this image targets — informational tag only, does not filter the base AMI (ami_filter_name already encodes it)."
}

variable "podmotion_agent_s3_uri" {
  type        = string
  description = "s3:// URI of the pre-compiled podmotion-agent binary (linux/amd64) to bake into the image."
}

variable "podmotion_preflight_s3_uri" {
  type        = string
  description = "s3:// URI of the podmotion-preflight-amazon.sh script to bake into the image."
}

variable "ansible_extra_vars" {
  type        = map(string)
  default     = {}
  description = "Extra vars passed through to the podmotion-node Ansible role (e.g. podmotion_version, selinux_module_install)."
}

variable "ami_tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to the produced AMI and its snapshots."
}

## -----------------------------------------------------------------------------
## Base AMI lookup
## -----------------------------------------------------------------------------

data "amazon-ami" "eks_base" {
  filters = {
    name                = var.ami_filter_name
    root-device-type    = "ebs"
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
  # al2023.pkrvars.hcl header comment: podmotion-eks-al2023-v0.1.0-YYYYMMDDHHMMSS
  build_timestamp = formatdate("YYYYMMDDhhmmss", timestamp())
  ami_name        = "${var.ami_name_prefix}-${var.podmotion_version}-${local.build_timestamp}"

  common_tags = merge(var.ami_tags, {
    Name                     = local.ami_name
    "podmotion/kubernetes-version" = var.kubernetes_version
    "podmotion/base-ami"     = data.amazon-ami.eks_base.id
  })
}

source "amazon-ebs" "podmotion_eks_node" {
  ami_name      = local.ami_name
  ami_regions   = distinct(concat([var.region], var.ami_regions))
  encrypt_boot  = var.encrypt_boot
  instance_type = var.instance_type
  region        = var.region
  source_ami    = data.amazon-ami.eks_base.id
  ssh_username  = "ec2-user"

  subnet_id                  = var.subnet_id != "" ? var.subnet_id : null
  associate_public_ip_address = var.associate_public_ip
  iam_instance_profile       = var.iam_instance_profile != "" ? var.iam_instance_profile : null

  tags     = local.common_tags
  run_tags = merge(local.common_tags, { Name = "packer-builder-${local.ami_name}" })

  # EKS-optimized AL2023 base images already carry an adequately-sized root
  # volume for kubelet/containerd; PodMotion's own additions (agent binary,
  # CRIU, buildah/skopeo) are small, so no explicit volume resize here.
}

## -----------------------------------------------------------------------------
## Build
## -----------------------------------------------------------------------------

build {
  name    = "podmotion-eks-node"
  sources = ["source.amazon-ebs.podmotion_eks_node"]

  # Fetch the pre-compiled agent binary and preflight script from S3 onto the
  # LOCAL machine running `packer build` (NOT the remote build instance) —
  # the ansible provisioner below runs ansible-playbook locally over SSH, so
  # the podmotion-node role's `copy` tasks need these files to already exist
  # under ../ansible/roles/podmotion-node/files/ before that step runs.
  provisioner "shell-local" {
    inline = [
      "set -euo pipefail",
      "aws s3 cp '${var.podmotion_agent_s3_uri}' ../ansible/roles/podmotion-node/files/podmotion-agent",
      "aws s3 cp '${var.podmotion_preflight_s3_uri}' ../ansible/roles/podmotion-node/files/podmotion-preflight-amazon.sh",
      "chmod +x ../ansible/roles/podmotion-node/files/podmotion-agent",
      "chmod +x ../ansible/roles/podmotion-node/files/podmotion-preflight-amazon.sh",
    ]
  }

  provisioner "ansible" {
    playbook_file   = "../ansible/playbook.yml"
    user            = "ec2-user"
    extra_arguments = ["--extra-vars", jsonencode(var.ansible_extra_vars)]
  }

  # Clean up the fetched binaries from the local ansible files/ dir so they
  # don't get committed to git or linger stale between builds.
  provisioner "shell-local" {
    inline = [
      "rm -f ../ansible/roles/podmotion-node/files/podmotion-agent",
      "rm -f ../ansible/roles/podmotion-node/files/podmotion-preflight-amazon.sh",
    ]
  }

  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
    custom_data = {
      podmotion_version  = var.podmotion_version
      kubernetes_version = var.kubernetes_version
      base_ami           = data.amazon-ami.eks_base.id
    }
  }
}
