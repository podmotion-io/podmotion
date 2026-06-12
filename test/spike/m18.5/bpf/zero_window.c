// SPDX-License-Identifier: GPL-2.0
/*
 * zero_window.c — spike variant of the TC egress zero-window hold.
 *
 * Unlike the production version (which uses a PM_ACTIVE_HOLDS map keyed by ifindex
 * and is loaded by the DaemonSet), this spike version is loaded directly onto a
 * SINGLE veth interface and holds ALL TCP connections egressing that interface.
 *
 * Usage:
 *   tc qdisc add dev <veth> clsact
 *   tc filter add dev <veth> egress bpf direct-action obj zero_window.o sec tc
 *
 * Remove:
 *   tc filter del dev <veth> egress
 *   tc qdisc del dev <veth> clsact
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Incremental TCP checksum update (RFC 1624 §3).
 * We zero out the window field only; old_win is the original value.
 */
static __always_inline void zero_window_csum_fixup(struct tcphdr *tcp, __u16 old_win)
{
    /* one's complement: new_csum = ~(~old_csum - old_win + 0)
     * simplified: csum -= old_win (with carry folding)
     */
    __u32 csum = (__u16)~bpf_ntohs(tcp->check);
    csum -= bpf_ntohs(old_win);
    csum  = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    tcp->check = bpf_htons((__u16)~csum);
}

SEC("tc")
int pm_spike_zero_window(struct __sk_buff *skb)
{
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

    if (tcp->window == 0)
        return TC_ACT_OK;

    __u16 old_win = tcp->window;
    tcp->window   = 0;
    zero_window_csum_fixup(tcp, old_win);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
