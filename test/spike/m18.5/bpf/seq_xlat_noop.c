// SPDX-License-Identifier: GPL-2.0
/*
 * seq_xlat_noop.c — spike relay: pure IP/MAC steering, seq_delta = 0.
 *
 * For the M18.5 spike, CRIU --tcp-established + --join-ns restores sockets with
 * exact seq/ack state (seq_delta = 0). This program is attached to the migration
 * netns veth on the DESTINATION node to verify that zero-delta steering is sufficient.
 *
 * If this passes (no seq discontinuity in tcpdump), the default relay tier requires
 * only IP/MAC steering, not seq arithmetic. If we see a seq gap here, the relay must
 * add seq translation — that finding changes the M19 design.
 *
 * Attach on destination node:
 *   tc qdisc add dev <migration-veth-host-side> clsact
 *   tc filter add dev <migration-veth-host-side> ingress bpf direct-action obj seq_xlat_noop.o sec tc
 *
 * The program passes all packets through TC_ACT_OK and emits a bpf_trace_printk for
 * every TCP packet so we can observe seq numbers in /sys/kernel/debug/tracing/trace_pipe.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * PM_SEQ_OBS: ring-buffer for observed (4-tuple, seq, ack) events.
 * Userspace reads this to verify seq continuity without pcap overhead.
 *
 * In the spike, we just use bpf_printk which is simpler; a ring buffer
 * would be the production approach.
 */

SEC("tc")
int pm_spike_seq_obs(struct __sk_buff *skb)
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

    /* Log seq/ack for every TCP segment crossing the relay boundary */
    bpf_printk("pm-relay: src=%x:%u dst=%x:%u seq=%u ack=%u\n",
               bpf_ntohl(ip->saddr), bpf_ntohs(tcp->source),
               bpf_ntohl(ip->daddr), bpf_ntohs(tcp->dest),
               bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
