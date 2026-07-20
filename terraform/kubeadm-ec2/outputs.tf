output "control_plane_public_ip" {
  description = "Public IP of the control-plane node."
  value       = aws_instance.control_plane.public_ip
}

output "worker_public_ip" {
  description = "Public IP of the worker node."
  value       = aws_instance.worker.public_ip
}

output "ssh_private_key_path" {
  description = "Local path to the generated SSH private key (0600)."
  value       = local_sensitive_file.ssh_private_key.filename
}

output "ssh_control_plane" {
  description = "Ready-to-run SSH command for the control-plane node."
  value       = "ssh -i ${local_sensitive_file.ssh_private_key.filename} -o StrictHostKeyChecking=no ubuntu@${aws_instance.control_plane.public_ip}"
}

output "ssh_worker" {
  description = "Ready-to-run SSH command for the worker node."
  value       = "ssh -i ${local_sensitive_file.ssh_private_key.filename} -o StrictHostKeyChecking=no ubuntu@${aws_instance.worker.public_ip}"
}

output "pod_cidr" {
  description = "Pod CIDR to pass as --pod-network-cidr to kubeadm init."
  value       = var.pod_cidr
}

output "allowed_ssh_cidr" {
  description = "The CIDR that was actually allowed SSH/API access (your detected public IP, or the override if set)."
  value       = local.ssh_allowed_cidr
}
