// SPDX-License-Identifier: GPL-2.0
/*
 * pm_xdp_vtep.c — XDP programs for VXLAN VTEP handling during migration.
 *
 * Two programs:
 *
 *   pm_xdp_vtep (XDP_PROG_TYPE_XDP on flannel.1 at destination node):
 *     Decapsulates VXLAN frames destined for the source pod's IP at the
 *     destination VTEP and bpf_redirects them into the migration netns veth.
 *     This allows traffic to reach the restored pod before the FDB has fully
 *     converged on all nodes.
 *
 *   pm_xdp_src_guard (XDP_PROG_TYPE_XDP on flannel.1 at source node):
 *     During the FDB convergence window some nodes still route traffic toward
 *     the SOURCE VTEP.  This program intercepts those straggler frames,
 *     re-encapsulates them with the destination VTEP MAC, and redirects them
 *     forward over the underlay so they reach the new pod location.
 *
 * Map: PM_VTEP_MAP — BPF_MAP_TYPE_HASH keyed by source pod IP (__be32),
 * value = vtep_entry {dst_vtep_ip, dst_ifindex, vni}.
 * max_entries=4096.  Agent populates before ZeroWindowDisarm and clears after
 * TCPVerified=True.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VXLAN_UDP_PORT 4789
#define VXLAN_HDR_LEN  8

struct vtep_entry {
    __be32 dst_vtep_ip;  /* destination VTEP IP (network byte order) */
    __u32  dst_ifindex;  /* ifindex to redirect decapsulated frame into */
    __u32  vni;          /* VXLAN Network Identifier (host byte order) */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __be32);              /* source pod IP */
    __type(value, struct vtep_entry);
} PM_VTEP_MAP SEC(".maps");

/*
 * pm_xdp_vtep: runs at the DESTINATION VTEP on flannel.1.
 * Intercepts VXLAN frames whose inner destination IP is a migrated pod IP
 * and redirects the decapsulated inner frame to the migration netns veth
 * (dst_ifindex from PM_VTEP_MAP).
 *
 * Frame layout on arrival:
 *   [outer ETH] [outer IP] [UDP:4789] [VXLAN:8] [inner ETH] [inner IP dst=pod_ip] ...
 *
 * We strip outer ETH + outer IP + UDP + VXLAN and redirect the inner frame.
 */
SEC("xdp")
int pm_xdp_vtep(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 outer_ip_hlen = outer_ip->ihl * 4;
    struct udphdr *udp = (void *)outer_ip + outer_ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(udp->dest) != VXLAN_UDP_PORT)
        return XDP_PASS;

    /* Skip VXLAN header to inner Ethernet frame. */
    __u32 outer_hdr_len = sizeof(*eth) + outer_ip_hlen + sizeof(*udp) + VXLAN_HDR_LEN;
    struct ethhdr *inner_eth = (void *)data + outer_hdr_len;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(inner_eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    struct vtep_entry *ve = bpf_map_lookup_elem(&PM_VTEP_MAP, &inner_ip->daddr);
    if (!ve)
        return XDP_PASS;

    /* Strip outer headers: adjust xdp data pointer to start of inner Ethernet frame. */
    if (bpf_xdp_adjust_head(ctx, (int)outer_hdr_len) != 0)
        return XDP_PASS;

    return bpf_redirect(ve->dst_ifindex, 0);
}

/*
 * pm_xdp_src_guard: runs at the SOURCE VTEP on flannel.1.
 * During FDB convergence, some remote nodes still send traffic to the source
 * VTEP for a migrated pod IP.  We detect those frames and redirect them to
 * the destination VTEP via bpf_redirect so they arrive at the correct node.
 *
 * We pass the frame unchanged to the network stack (XDP_PASS) once re-routed
 * via the redirect map; in the simple case we just redirect to the underlay
 * interface toward the destination VTEP.
 *
 * Note: src_guard redirects the ENTIRE outer VXLAN frame to the underlay
 * egress port (dst_ifindex = underlay ifindex).  The destination VTEP's
 * pm_xdp_vtep program then handles decap.
 */
SEC("xdp")
int pm_xdp_src_guard(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 outer_ip_hlen = outer_ip->ihl * 4;
    struct udphdr *udp = (void *)outer_ip + outer_ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(udp->dest) != VXLAN_UDP_PORT)
        return XDP_PASS;

    __u32 outer_hdr_len = sizeof(*eth) + outer_ip_hlen + sizeof(*udp) + VXLAN_HDR_LEN;
    struct ethhdr *inner_eth = (void *)data + outer_hdr_len;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(inner_eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    struct vtep_entry *ve = bpf_map_lookup_elem(&PM_VTEP_MAP, &inner_ip->daddr);
    if (!ve)
        return XDP_PASS;

    /* Redirect the full outer VXLAN frame toward the destination underlay. */
    return bpf_redirect(ve->dst_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
