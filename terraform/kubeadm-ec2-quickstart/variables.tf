variable "aws_region" {
  description = <<-EOT
    AWS region to deploy the kubeadm proving-ground cluster into. Must be one
    of the regions the golden AMI (var.ami_owner_account_id) is actually
    copied to, or the data "aws_ami" lookup will fail at apply-time — this
    list is kept in sync by hand with images/capi/packer/kubeadm-ubuntu.pkrvars.hcl's
    ami_regions var; update both together if the AMI's region footprint changes.
  EOT
  type        = string
  default     = "us-west-2"

  validation {
    condition = contains(
      ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1"],
      var.aws_region
    )
    error_message = "aws_region must be one of the regions the golden AMI is copied to: us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1. See images/capi/packer/kubeadm-ubuntu.pkrvars.hcl (ami_regions) — build/copy the AMI into a new region there before adding it here."
  }
}

variable "cluster_name" {
  description = "Short name used to tag/prefix all resources (e.g. \"podmotion-ec2\"). Defaults to a name distinct from terraform/kubeadm-ec2's own default (\"podmotion-kubeadm\") so this quickstart fork can be applied in the same AWS account/region as that module's live-applied resources without colliding on globally-unique-per-account names like the SSH key pair (aws_key_pair.key_name)."
  type        = string
  default     = "podmotion-kubeadm-quickstart"
}

variable "longhorn_disk_gb" {
  description = "Size in GB of the dedicated EBS volume attached to every node (control-plane + workers) for Longhorn backend storage. Formatted/mounted by the deploy step, not by Terraform."
  type        = number
  default     = 30
}

variable "worker_count" {
  description = "Number of worker nodes. Live pod migration needs at least 2 schedulable nodes (source + destination) — the control-plane is tainted NoSchedule, so a single worker leaves nothing to migrate TO. Default of 2 matches the KVM standing cluster's 1-control-plane + 2-worker topology."
  type        = number
  default     = 2
}

variable "instance_type" {
  description = "EC2 instance type for both the control-plane and worker node. t3.large gives CRIU/checkpoint work enough headroom without being expensive to leave running."
  type        = string
  default     = "t3.large"
}

variable "root_volume_gb" {
  description = "Root EBS volume size in GB for each node."
  type        = number
  default     = 40
}

variable "vpc_cidr" {
  description = "CIDR block for the dedicated proving-ground VPC."
  type        = string
  default     = "10.60.0.0/16"
}

variable "public_subnet_cidrs" {
  description = <<-EOT
    CIDR blocks for the public subnets, one per node, spread across distinct
    Availability Zones for HA (control-plane in AZ index 0, worker in AZ index
    1) — same VPC, cross-AZ traffic, not cross-region (kubeadm's control plane
    is not designed to tolerate cross-region etcd/API-server latency).
  EOT
  type    = list(string)
  default = ["10.60.1.0/24", "10.60.2.0/24"]
}

variable "pod_cidr" {
  description = "Kubernetes pod CIDR passed to kubeadm init (--pod-network-cidr). Kept distinct from the VPC CIDR to avoid overlap with whatever CNI gets installed."
  type        = string
  default     = "10.244.0.0/16"
}

variable "ssh_allowed_cidr_override" {
  description = "Optional CIDR to allow SSH from, overriding the auto-detected caller IP (data.http.my_public_ip). Leave null to auto-detect at apply-time — this is the default, matches this project's own \"SSH locked to caller's IP at apply-time\" convention."
  type        = string
  default     = null
}

variable "ami_owner_account_id" {
  description = <<-EOT
    AWS account ID that owns the golden "podmotion-io-kubeadm-ubuntu-*" AMI
    (built via images/capi/packer/kubeadm-ubuntu.pkr.hcl + the k8s-prereqs/
    podmotion-node Ansible roles — containerd, kubeadm/kubelet/kubectl, and
    CRIU pre-baked). Defaults to the PodMotion maintainer's own account,
    where this AMI already exists.

    If you are NOT that account, this default will not resolve to any AMI
    and `terraform apply` will fail at the data "aws_ami" lookup. You have
    two options:
      1. Get the golden AMI shared/copied into your own AWS account, then
         set this variable to your account ID (or the AMI owner's, if
         sharing across accounts and matching the name filter).
      2. Build your own copy of the golden AMI in your account by running
         the existing Packer template yourself:
           cd images/capi/packer
           packer init kubeadm-ubuntu.pkr.hcl
           packer build -var-file=kubeadm-ubuntu.pkrvars.hcl kubeadm-ubuntu.pkr.hcl
         then set this variable to your own account ID.
    Publishing/sharing the AMI itself is out of scope for this module.
  EOT
  type        = string
  default     = "868558231918"
}

variable "demo_web_node_port" {
  description = "NodePort the podmotion-demo web UI is exposed on (must match charts/podmotion-demo/values.yaml web.nodePort). Used both to open the security group and to compute the podmotion_demo_url output. Terraform does not install the demo chart itself — that's a manual helm install after kubeadm bootstrap, same as the kubeadm bootstrap itself — this just reserves the network path and predicts the URL."
  type        = number
  default     = 30080
}
