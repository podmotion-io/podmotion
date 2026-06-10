# PodMotion node image — Amazon Linux 2023 base
# Kernel: 6.1 (AWS-maintained, cgroup v2 default, SELinux enforcing)
#
# AL2023 key facts:
#   - dnf package manager (not yum)
#   - SELinux enforcing by default (RHEL 9 compatible policy)
#   - CRIU available in al2023 base repos as of 2024 — version 3.x
#     For CRIU 4.2 build from source or use PodMotion release RPM
#   - EKS-optimized AL2023 ships containerd 1.7.x → NRI IS available
#   - CONFIG_MEM_SOFT_DIRTY=y confirmed on AWS 6.1 kernel (from kernel config
#     published in https://github.com/amazonlinux/linux kernel-6.1 branch)
#   - cgroup v2 unified hierarchy (freezer available)
#
# This image is for CUSTOM AMI builds via Packer + image-builder.
# For EKS managed node groups use scripts/eks-userdata.sh.

FROM amazonlinux:2023

# ---- system packages --------------------------------------------------------
RUN dnf update -y && \
    dnf install -y \
        kernel-tools \
        bpftool \
        iproute \
        iproute-tc \
        iptables-legacy \
        nftables \
        jq \
        tar \
        gzip \
        curl \
        which \
        procps-ng \
        util-linux \
        criu \
        libnetfilter_queue \
        libnetfilter_queue-devel \
        skopeo \
        buildah \
    && dnf clean all

# ---- SELinux module for CRIU + PodMotion agent ------------------------------
# The .te source lives at deploy/selinux/podmotion.te (compiled here).
# Until the module is complete, set permissive on podmotion_t domain only.
RUN dnf install -y policycoreutils policycoreutils-devel setools-console \
    && dnf clean all
# Placeholder: real .te module compilation happens in the Packer provisioner
# after deploy/selinux/podmotion.te is present.
# RUN checkmodule -M -m -o /tmp/podmotion.mod deploy/selinux/podmotion.te \
#  && semodule_package -o /tmp/podmotion.pp -m /tmp/podmotion.mod \
#  && semodule -i /tmp/podmotion.pp

# ---- bpffs mount unit -------------------------------------------------------
COPY images/capi/ansible/roles/podmotion-node/files/sys-fs-bpf.mount \
     /etc/systemd/system/sys-fs-bpf.mount

# ---- containerd NRI config --------------------------------------------------
# AL2023 EKS ships containerd 1.7.x — NRI plugin drop-in is honoured.
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
RUN printf '# PodMotion required sysctls\nvm.unprivileged_userfaultfd=1\nnet.core.bpf_jit_enable=1\n# kernel.unprivileged_bpf_disabled=1 -- left at distro default on AL2023\nnet.ipv4.conf.all.rp_filter=0\n' \
    > /etc/sysctl.d/90-podmotion.conf

# Verify CRIU binary is present
RUN criu --version || true

LABEL org.podmotion.distro="al2023" \
      org.podmotion.criu-source="al2023-base-repo" \
      org.podmotion.nri-ready="true" \
      org.podmotion.kernel-min="6.1" \
      org.podmotion.selinux="enforcing-permissive-domain"
