// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * xdp_bridge.c — XDP program that bridges packets from the source pod IP to
 * the destination via a GENEVE tunnel during the cutover window.
 *
 * Lifecycle:
 *   1. Agent calls ArmXDPBridge(srcIP, dstIP, genevePort) — populates PM_BRIDGE_MAP.
 *   2. XDP program rewrites dest IP to the GENEVE endpoint (outer IP), encapsulates
 *      with a GENEVE header, and redirects via bpf_redirect_map.
 *   3. After EndpointSlice handoff completes and TrafficVerified=True, agent calls
 *      DisarmXDPBridge(srcIP) — removes the map entry, restoring normal forwarding.
 *
 * GENEVE was chosen over VXLAN because its TLV option space lets us carry the
 * original source IP as metadata, which the destination agent uses to correlate
 * with the restored pod without relying on source IP preservation by the kernel.
 *
 * ADR-0017: TCP preservation is v0.2 — v0.1 never loads this program (TIER_4 cold).
 * The program stubs here are compiled and linked but the Go agent only loads them
 * on nodes that advertise NetworkContinuity=true in their NodeMigrationCapacity.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GENEVE_PORT 6081

/* PM_BRIDGE_MAP: source pod IP → (destination IP, GENEVE port).
 * Updated atomically by the Go agent via bpf_map_update_elem.
 * Keyed by __be32 (network byte order) to match XDP packet view.
 */
struct bridge_entry {
    __be32 dst_ip;
    __u16  geneve_port; /* host byte order — converted at runtime */
    __u8   _pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);              /* source pod IP (net order) */
    __type(value, struct bridge_entry);
} PM_BRIDGE_MAP SEC(".maps");

/* TX port map — populated by Go agent with the egress ifindex for the GENEVE tunnel.
 * We use BPF_MAP_TYPE_DEVMAP so bpf_redirect_map works natively with XDP.
 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} PM_TUNNEL_IFACE SEC(".maps");

SEC("xdp")
int pm_xdp_bridge(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only intercept traffic destined for the source pod IP. */
    struct bridge_entry *entry = bpf_map_lookup_elem(&PM_BRIDGE_MAP, &ip->daddr);
    if (!entry)
        return XDP_PASS;

    /*
     * STUB: Full GENEVE encapsulation requires adjusting the packet headroom,
     * writing the outer Ethernet/IP/UDP/GENEVE headers, and updating checksums.
     * Performing this correctly requires bpf_xdp_adjust_head which needs careful
     * bounds re-checking after the headroom change — deferring full implementation
     * to v0.2 when TCP preservation is activated (ADR-0017).
     *
     * The stub logs the redirect intent and passes the packet unchanged so that
     * the Go agent can exercise the load/unload lifecycle in integration tests
     * without actual encapsulation side-effects.
     */
    bpf_printk("pm_xdp_bridge: redirect src=%x dst=%x to geneve dst=%x port=%u\n",
               bpf_ntohl(ip->saddr),
               bpf_ntohl(ip->daddr),
               bpf_ntohl(entry->dst_ip),
               entry->geneve_port);

    /* Pass through so existing routing handles the packet in the stub. */
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
