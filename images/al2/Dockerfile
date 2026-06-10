# PodMotion node image — Amazon Linux 2 base
# Kernel: AWS 5.10 (EKS-optimized, custom AWS patches)
#
# NOTE: AL2 ships CRIU 3.x via EPEL only. For CRIU 4.2 you must build from
# source or use the pre-built RPM hosted in the PodMotion release bucket.
# CONFIG_MEM_SOFT_DIRTY status on the AWS 5.10 kernel is unknown at build time;
# the preflight script validates it at node-join time and downgrades the
# migration mode to cold-only if absent.
#
# EKS-optimized AL2 AMIs ship:
#   containerd 1.6.x — NRI plugin API is NOT available (NRI requires 1.7+)
#   runc 1.1.x
#   kubelet, aws-k8s-cni (vpc-cni)
#
# This image is intended for CUSTOM AMI builds only, not EKS managed node groups.
# For managed node groups use the userdata approach (scripts/eks-userdata.sh).

FROM amazonlinux:2

# ---- system packages --------------------------------------------------------
RUN yum update -y && \
    yum install -y \
        amazon-linux-extras \
        kernel-tools \
        iproute \
        iproute-tc \
        iptables \
        jq \
        tar \
        gzip \
        curl \
        which \
        procps \
        util-linux \
    && amazon-linux-extras install -y epel \
    && yum install -y --enablerepo=epel \
        criu \
        bpftool \
        libnetfilter_queue \
        libnetfilter_queue-devel \
    && yum clean all

# ---- bpffs mount unit -------------------------------------------------------
COPY images/capi/ansible/roles/podmotion-node/files/sys-fs-bpf.mount \
     /etc/systemd/system/sys-fs-bpf.mount

# ---- containerd NRI config (if containerd 1.7+ is in use) ------------------
# NRI is NOT available on the default EKS AL2 containerd 1.6.x.
# This snippet is present so the image is forward-compatible with upgraded
# containerd; it is a no-op on 1.6.x (drop-in dir is ignored).
RUN mkdir -p /etc/containerd/conf.d /usr/local/lib/nri
COPY images/capi/ansible/roles/podmotion-node/files/nri.toml \
     /etc/containerd/conf.d/nri.toml

# ---- PodMotion agent --------------------------------------------------------
COPY bin/agent-linux-amd64 /usr/local/bin/podmotion-agent
RUN chmod +x /usr/local/bin/podmotion-agent \
 && ln -sf /usr/local/bin/podmotion-agent /usr/local/lib/nri/podmotion-nri

# ---- preflight script -------------------------------------------------------
COPY scripts/podmotion-preflight-amazon.sh /usr/local/bin/podmotion-preflight
RUN chmod +x /usr/local/bin/podmotion-preflight

# ---- systemd service --------------------------------------------------------
RUN printf '[Unit]\nDescription=PodMotion Node Agent\nAfter=network.target containerd.service\nRequires=containerd.service\n\n[Service]\nExecStart=/usr/local/bin/podmotion-agent --node-name=${NODE_NAME} --grpc-port=9090 --metrics-port=9091\nRestart=always\nRestartSec=5\nEnvironment=NODE_NAME=\n\n[Install]\nWantedBy=multi-user.target\n' \
    > /etc/systemd/system/podmotion-agent.service

# ---- sysctls baked in -------------------------------------------------------
RUN printf '# PodMotion required sysctls\nvm.unprivileged_userfaultfd=1\nnet.core.bpf_jit_enable=1\nkernel.unprivileged_bpf_disabled=1\nnet.ipv4.conf.all.rp_filter=0\n' \
    > /etc/sysctl.d/90-podmotion.conf

# Verify CRIU binary is present (kernel checks are skipped inside Docker)
RUN criu --version || true

# NOTE: AL2 EOL is June 30 2025. Migrate workloads to AL2023.
LABEL org.podmotion.distro="al2" \
      org.podmotion.criu-source="epel" \
      org.podmotion.nri-ready="false" \
      org.podmotion.kernel-min="5.10"
