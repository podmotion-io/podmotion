#!/usr/bin/env bash
# ssh.sh <ip> "<cmd>" — same calling convention as the KVM substrate's
# own ssh.sh helper (path to your ssh.sh script). Usage: bash ssh.sh $CP1 "sudo systemctl status kubelet"
set -euo pipefail
ip="$1"; shift
exec ssh -i "$(dirname "$0")/podmotion-kubeadm-quickstart-ssh-key.pem" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 -o LogLevel=ERROR \
  "ubuntu@$ip" "$@"
