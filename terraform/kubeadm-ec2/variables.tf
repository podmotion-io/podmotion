variable "aws_region" {
  description = "AWS region to deploy the kubeadm proving-ground cluster into."
  type        = string
  default     = "us-east-2"
}

variable "cluster_name" {
  description = "Short name used to tag/prefix all resources (e.g. \"podmotion-ec2\")."
  type        = string
  default     = "podmotion-kubeadm"
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
