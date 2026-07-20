variable "aws_region" {
  description = "AWS region to deploy the EKS proving-ground cluster into."
  type        = string
  default     = "us-east-2"
}

variable "cluster_name" {
  description = "Name of the EKS cluster."
  type        = string
  default     = "podmotion-eks"
}

variable "kubernetes_version" {
  description = "EKS control-plane Kubernetes version."
  type        = string
  default     = "1.31"
}

variable "vpc_cidr" {
  description = "CIDR block for the dedicated EKS VPC."
  type        = string
  default     = "10.61.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for the public subnets EKS's managed node group runs in. EKS requires subnets in at least 2 distinct AZs."
  type        = list(string)
  default     = ["10.61.1.0/24", "10.61.2.0/24"]
}

variable "node_instance_type" {
  description = "EC2 instance type for the managed node group."
  type        = string
  default     = "t3.large"
}

variable "node_desired_size" {
  description = "Desired number of worker nodes."
  type        = number
  default     = 2
}

variable "node_min_size" {
  description = "Minimum number of worker nodes."
  type        = number
  default     = 2
}

variable "node_max_size" {
  description = "Maximum number of worker nodes."
  type        = number
  default     = 3
}

variable "custom_node_ami_id" {
  description = <<-EOT
    Optional custom AMI ID for the managed node group's worker nodes — the
    "podmotion.io" golden EKS-node AMI built via images/capi/packer/eks-node.pkr.hcl
    (PodMotion agent, NRI plugin, CRIU, zero-window eBPF datapath baked onto the
    official EKS-optimized AL2023 base image). Leave null (the default) to use
    AWS's own default EKS-optimized AMI for the node group's ami_type instead —
    that's what happens until this is explicitly set to a real ami-xxxxxxxx value
    (e.g. via -var or a .tfvars file) once the podmotion.io AMI build completes.
  EOT
  type        = string
  default     = null
}
