output "control_plane_public_ip" {
  description = "Public IP of the control-plane node."
  value       = aws_instance.control_plane.public_ip
}

output "worker_public_ips" {
  description = "Public IPs of the worker nodes."
  value       = aws_instance.worker[*].public_ip
}

output "ssh_private_key_path" {
  description = "Local path to the generated SSH private key (0600)."
  value       = local_sensitive_file.ssh_private_key.filename
}

output "ssh_control_plane" {
  description = "Ready-to-run SSH command for the control-plane node."
  value       = "ssh -i ${local_sensitive_file.ssh_private_key.filename} -o StrictHostKeyChecking=no ubuntu@${aws_instance.control_plane.public_ip}"
}

output "ssh_workers" {
  description = "Ready-to-run SSH commands for each worker node."
  value       = [for w in aws_instance.worker : "ssh -i ${local_sensitive_file.ssh_private_key.filename} -o StrictHostKeyChecking=no ubuntu@${w.public_ip}"]
}

output "pod_cidr" {
  description = "Pod CIDR to pass as --pod-network-cidr to kubeadm init."
  value       = var.pod_cidr
}

output "allowed_ssh_cidr" {
  description = "The CIDR that was actually allowed SSH/API access (your detected public IP, or the override if set)."
  value       = local.ssh_allowed_cidr
}

output "podmotion_demo_url" {
  description = "URL for the podmotion-demo web UI once the chart is installed post-bootstrap (a NodePort service, exposed cluster-wide, so the control-plane's IP works regardless of which node the pod lands on). Not reachable until kubeadm is bootstrapped and charts/podmotion-demo (or the parent podmotion chart with podmotion-demo.enabled=true) is helm-installed."
  value       = "http://${aws_instance.control_plane.public_ip}:${var.demo_web_node_port}"
}
