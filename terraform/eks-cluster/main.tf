# eks-cluster — a minimal managed EKS cluster, the final leg of the
# KVM-matrix -> EC2 kubeadm -> EKS -> public-push roadmap.
#
# Deliberately minimal: 2 public subnets (EKS requires >=2 AZs), no NAT
# gateway (nodes get public IPs directly — cheaper for a proving ground,
# same "prove it works, optimize later" posture as the kubeadm-ec2 module),
# one managed node group. EKS's control plane is fully AWS-managed, so
# unlike kubeadm-ec2 there's no SSH-key/bootstrap story here — cluster
# access is via aws eks update-kubeconfig once this is applied.

locals {
  name_prefix = var.cluster_name
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ── Networking ────────────────────────────────────────────────────────────

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name                                         = "${local.name_prefix}-vpc"
    "kubernetes.io/cluster/${local.name_prefix}" = "shared"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                                         = "${local.name_prefix}-public-${count.index}"
    "kubernetes.io/cluster/${local.name_prefix}" = "shared"
    "kubernetes.io/role/elb"                     = "1"
  }
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

# ── IAM: EKS cluster role ────────────────────────────────────────────────

data "aws_iam_policy_document" "eks_cluster_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${local.name_prefix}-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_assume_role.json
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# ── IAM: managed node group role ─────────────────────────────────────────

data "aws_iam_policy_document" "node_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${local.name_prefix}-node-role"
  assume_role_policy = data.aws_iam_policy_document.node_assume_role.json
}

resource "aws_iam_role_policy_attachment" "node_worker_policy" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_ecr_readonly" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# ── EKS cluster + managed node group ─────────────────────────────────────

resource "aws_eks_cluster" "this" {
  name     = local.name_prefix
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = aws_subnet.public[*].id
    endpoint_public_access  = true
    endpoint_private_access = false
  }

  depends_on = [aws_iam_role_policy_attachment.cluster_policy]
}

## -----------------------------------------------------------------------------
## Optional custom node AMI — the "podmotion.io" golden EKS-node image
## -----------------------------------------------------------------------------
# EKS managed node groups only accept a custom AMI via a launch template with
# ami_type="CUSTOM" — the launch template's own image_id then takes over from
# whatever ami_type would otherwise select. AL2023-based custom AMIs (which the
# podmotion.io EKS AMI is, per images/capi/packer/eks-node.pkr.hcl's base image)
# bootstrap via a plain nodeadm NodeConfig document as user_data, not the older
# AL2/bootstrap.sh shell-script form. Only created when custom_node_ami_id is
# actually set — with it left at the default null, the node group falls back to
# ami_type="AL2023_x86_64_STANDARD" (AWS's own default) and no launch template
# is created at all, so this is a no-op until the AMI is real and this variable
# is explicitly pointed at it.

resource "aws_launch_template" "custom_node" {
  count = var.custom_node_ami_id != null ? 1 : 0

  name_prefix = "${local.name_prefix}-node-"
  image_id    = var.custom_node_ami_id

  user_data = base64encode(<<-EOT
    apiVersion: node.eks.aws/v1alpha1
    kind: NodeConfig
    spec:
      cluster:
        name: ${local.name_prefix}
        apiServerEndpoint: ${aws_eks_cluster.this.endpoint}
        certificateAuthority: ${aws_eks_cluster.this.certificate_authority[0].data}
        cidr: ${aws_eks_cluster.this.kubernetes_network_config[0].service_ipv4_cidr}
  EOT
  )

  tag_specifications {
    resource_type = "instance"
    tags           = { Name = "${local.name_prefix}-node" }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${local.name_prefix}-default"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = aws_subnet.public[*].id
  instance_types  = [var.node_instance_type]
  ami_type        = var.custom_node_ami_id != null ? "CUSTOM" : "AL2023_x86_64_STANDARD"

  dynamic "launch_template" {
    for_each = var.custom_node_ami_id != null ? [1] : []
    content {
      id      = aws_launch_template.custom_node[0].id
      version = aws_launch_template.custom_node[0].latest_version
    }
  }

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker_policy,
    aws_iam_role_policy_attachment.node_cni_policy,
    aws_iam_role_policy_attachment.node_ecr_readonly,
  ]
}
