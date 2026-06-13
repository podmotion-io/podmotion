// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * zero_window.c — TC egress program that rewrites TCP window=0 to hold senders.
 *
 * Loaded on the SOURCE NODE (privileged DaemonSet) during the freeze window only.
 * Agent arms the hold by adding the source pod veth ifindex to PM_ACTIVE_HOLDS
 * before issuing CRIU freeze; disarms by removing the entry post-cutover.
 *
 * Why TC egress (not XDP)? We need to see the full Ethernet frame after IP routing
 * has already happened — TC egress runs after traffic is committed to the veth,
 * which is what lets us target exactly one pod's traffic without a BPF redirect map.
 *
 * TCP PAWS note: we set window=0 without touching SEQ/ACK — remote senders will
 * probe with zero-window probes, which we hold until the bridge is armed.
 * Receivers will still ACK probes to prevent spurious RSTs.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* PM_ACTIVE_HOLDS: set of ifindices currently under zero-window hold.
 * Agent adds/removes entries via bpf_map_update_elem / bpf_map_delete_elem.
 * BPF_MAP_TYPE_HASH used for O(1) lookup — expected to hold at most ~100 entries
 * per node (one per concurrent migration freeze).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* ifindex */
    __type(value, __u8);  /* 1 = active hold */
} PM_ACTIVE_HOLDS SEC(".maps");

/*
 * recompute_tcp_checksum: incremental update per RFC 1624.
 * We only change the window field, so we can use the one-complement trick:
 *   new_csum = old_csum - old_window + new_window (one's complement arithmetic)
 * Saves a full TCP checksum scan over the payload.
 */
static __always_inline void update_tcp_window_csum(struct tcphdr *tcp, __u16 old_win)
{
    __u32 csum = ~bpf_ntohs(tcp->check);
    csum -= bpf_ntohs(old_win);
    /* new window is 0 so we just subtract the old value */
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    tcp->check = bpf_htons((__u16)~csum);
}

SEC("tc")
int pm_zero_window_hold(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;

    /* Fast path: most packets are not under hold. */
    __u8 *active = bpf_map_lookup_elem(&PM_ACTIVE_HOLDS, &ifindex);
    if (!active)
        return TC_ACT_OK;

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hlen = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    /* Nothing to do if window is already 0 (handles re-entry idempotency). */
    if (tcp->window == 0)
        return TC_ACT_OK;

    __u16 old_win = tcp->window;
    tcp->window   = 0;
    update_tcp_window_csum(tcp, old_win);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
