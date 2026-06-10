# Packer variables for PodMotion EKS AMI — Amazon Linux 2023
# Usage:
#   packer build -var-file=images/capi/packer/al2023.pkrvars.hcl \
#                images/capi/packer/eks-node.pkr.hcl
#
# The build produces an AMI registered in the AWS account for use with EKS
# managed node groups via a custom launch template.
#
# Requires:
#   - packer >= 1.10
#   - amazon plugin: packer init .
#   - AWS credentials with ec2:CreateImage, ec2:RunInstances, etc.

# ---- Base AMI ----------------------------------------------------------------
# Use the latest EKS-optimized AL2023 AMI as the base so kubelet, containerd,
# and VPC CNI are pre-installed. PodMotion layers on top.
# To find the latest: aws ssm get-parameter \
#   --name /aws/service/eks/optimized-ami/1.29/amazon-linux-2023/x86_64/standard/recommended/image_id \
#   --query Parameter.Value --output text
ami_filter_name         = "amazon-eks-node-al2023-x86_64-standard-1.29-*"
ami_filter_owner        = "602401143452"  # AWS EKS AMI account

# ---- Build instance ----------------------------------------------------------
instance_type           = "m5.xlarge"
region                  = "us-west-2"
# Subnet must have internet access (NAT or IGW) for dnf installs
subnet_id               = ""   # leave empty to use default VPC
associate_public_ip     = true
iam_instance_profile    = ""   # instance profile with S3 read for agent binary

# ---- Output AMI --------------------------------------------------------------
ami_name_prefix         = "podmotion-eks-al2023"
# Final name: podmotion-eks-al2023-v0.1.0-YYYYMMDDHHMMSS
podmotion_version       = "v0.1.0"
ami_regions             = ["us-west-2", "us-east-1"]
encrypt_boot            = false

# ---- EKS version to target ---------------------------------------------------
kubernetes_version      = "1.29"

# ---- PodMotion agent source --------------------------------------------------
# S3 URI of the pre-compiled podmotion-agent binary for linux/amd64.
# Must be readable by the build instance profile.
podmotion_agent_s3_uri  = "s3://your-bucket/podmotion/releases/v0.1.0/podmotion-agent-linux-amd64"
podmotion_preflight_s3_uri = "s3://your-bucket/podmotion/releases/v0.1.0/podmotion-preflight-amazon.sh"

# ---- Ansible role variables -------------------------------------------------
# Passed to ansible-playbook as --extra-vars
ansible_extra_vars = {
  podmotion_version = "v0.1.0"
  # Set to true once deploy/selinux/podmotion.te is complete (see KNOWN ISSUES)
  selinux_module_install = false
}

# ---- Tags --------------------------------------------------------------------
ami_tags = {
  "podmotion/version"          = "v0.1.0"
  "podmotion/distro"           = "al2023"
  "podmotion/kubernetes"       = "1.29"
  "podmotion/nri-ready"        = "true"
  "podmotion/criu-version"     = "3.x-al2023-base"
  "podmotion/mem-soft-dirty"   = "true"
}
