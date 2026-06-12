// SPDX-License-Identifier: GPL-2.0
/*
 * pm_relay.c — TC-BPF relay programs for TCP sequence/ack translation.
 *
 * Two programs share a single source file so they can share the PM_SEQ_XLAT
 * map definition:
 *
 *   pm_relay_tc_egress  — attached to flannel.1 TC egress (outgoing direction).
 *     Outgoing means: pod → peer.  We apply the POSITIVE delta:
 *       seq  += seq_delta
 *       ack  += ack_delta
 *       TSval += ts_delta
 *       SACK block left/right edges += ack_delta
 *
 *   pm_relay_tc_ingress — attached to flannel.1 TC ingress (incoming direction).
 *     Incoming means: peer → pod.  We apply the NEGATIVE delta:
 *       seq  -= seq_delta   (peer thinks it is talking to old socket)
 *       ack  -= ack_delta
 *       TSecr += ts_delta   (peer's echo of our TSval; must be shifted the same way)
 *       SACK edges += ack_delta
 *
 * The asymmetry on TSecr is intentional: the peer echoes what we sent them
 * (TSval), so TSecr seen on ingress must be un-shifted by the same ts_delta
 * we applied outbound.  See ADR-0049 §PAWS.
 *
 * Both programs recompute the TCP checksum incrementally (RFC 1624) and the
 * outer VXLAN/UDP checksum (zeroed per RFC 7348 §6 for VXLAN-in-UDP).
 *
 * Map: PM_SEQ_XLAT — BPF_MAP_TYPE_HASH (NOT LRU; entries are pinned until
 * the migration agent explicitly removes them to guarantee ADR-0012 ordering).
 * max_entries=4096.  Key = 4-tuple {src_ip, dst_ip, src_port, dst_port}.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ── PM_SEQ_XLAT map ──────────────────────────────────────────────────────── */

/* FourTuple — network-byte-order 4-tuple used as map key.
 * src/dst are from the inner TCP segment's perspective. */
struct four_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

/* SeqXlatEntry — sequence/ack/timestamp deltas for one migrated connection. */
struct seq_xlat_entry {
    __s32 seq_delta;     /* host byte order; added to seq on egress */
    __s32 ack_delta;     /* host byte order; added to ack on egress */
    __s32 ts_delta;      /* host byte order; added to TSval/TSecr */
    __u8  wscale;        /* window scale factor for this connection */
    __u8  sack_present;  /* 1 if connection uses SACK */
    __u8  state;         /* 0=inactive 1=active 2=teardown */
    __u8  pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct four_tuple);
    __type(value, struct seq_xlat_entry);
} PM_SEQ_XLAT SEC(".maps");

/* ── VXLAN framing constants ─────────────────────────────────────────────── */

#define VXLAN_UDP_PORT   4789
#define VXLAN_HDR_LEN    8   /* flags(4) + VNI(3) + reserved(1) */

/* ── Checksum helpers ─────────────────────────────────────────────────────── */

/*
 * csum_diff32: incremental checksum update for a 32-bit field change.
 * RFC 1624: new_csum = ~(~old_csum - old_val + new_val)
 * Returns the updated checksum in network byte order.
 */
static __always_inline __sum16 csum_diff32(__sum16 old_csum, __be32 old_val, __be32 new_val)
{
    __u32 csum = (~bpf_ntohs(old_csum)) & 0xffff;
    csum -= (bpf_ntohl(old_val) >> 16);
    csum -= (bpf_ntohl(old_val) & 0xffff);
    csum += (bpf_ntohl(new_val) >> 16);
    csum += (bpf_ntohl(new_val) & 0xffff);
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    return bpf_htons((__u16)~csum);
}

/*
 * csum_diff16: incremental checksum update for a 16-bit field change.
 */
static __always_inline __sum16 csum_diff16(__sum16 old_csum, __be16 old_val, __be16 new_val)
{
    __u32 csum = (~bpf_ntohs(old_csum)) & 0xffff;
    csum -= bpf_ntohs(old_val);
    csum += bpf_ntohs(new_val);
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    return bpf_htons((__u16)~csum);
}

/* ── VXLAN/UDP frame parsing ─────────────────────────────────────────────── */

/*
 * parse_vxlan_inner_tcp: locate the inner Ethernet/IP/TCP headers inside a
 * VXLAN-encapsulated frame.  All pointer-out parameters are set on success.
 * Returns 0 on success, TC_ACT_OK (pass unchanged) on failure/mismatch.
 *
 * Frame layout on flannel.1:
 *   [outer ETH] [outer IP] [UDP dport=4789] [VXLAN hdr 8B]
 *   [inner ETH] [inner IP] [inner TCP]
 */
static __always_inline int parse_vxlan_inner_tcp(
    struct __sk_buff *skb,
    struct iphdr    **out_inner_ip,
    struct tcphdr   **out_tcp,
    void            **data_end)
{
    void *data = (void *)(long)skb->data;
    *data_end  = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > *data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > *data_end)
        return TC_ACT_OK;

    if (outer_ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u32 outer_ip_hlen = outer_ip->ihl * 4;
    struct udphdr *udp = (void *)outer_ip + outer_ip_hlen;
    if ((void *)(udp + 1) > *data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(udp->dest) != VXLAN_UDP_PORT)
        return TC_ACT_OK;

    /* Skip VXLAN header (8 bytes) + inner Ethernet header. */
    void *vxlan_inner_eth = (void *)(udp + 1) + VXLAN_HDR_LEN;
    struct ethhdr *inner_eth = vxlan_inner_eth;
    if ((void *)(inner_eth + 1) > *data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(inner_eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > *data_end)
        return TC_ACT_OK;

    if (inner_ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 inner_ip_hlen = inner_ip->ihl * 4;
    struct tcphdr *tcp = (void *)inner_ip + inner_ip_hlen;
    if ((void *)(tcp + 1) > *data_end)
        return TC_ACT_OK;

    *out_inner_ip = inner_ip;
    *out_tcp      = tcp;
    return 0;
}

/* ── TCP option rewriting ─────────────────────────────────────────────────── */

#define TCPOPT_EOL   0
#define TCPOPT_NOP   1
#define TCPOPT_MSS   2
#define TCPOPT_WSCALE 3
#define TCPOPT_SACK_PERM 4
#define TCPOPT_SACK  5
#define TCPOPT_TS    8

/*
 * rewrite_tcp_options: scan TCP options and patch TSval (egress) or TSecr
 * (ingress) and SACK block edges.
 *
 * is_egress==1  → patch TSval field (+ts_delta) + SACK left/right (+ack_delta)
 * is_egress==0  → patch TSecr field (+ts_delta) + SACK left/right (+ack_delta)
 *
 * Returns the net checksum change as a 32-bit accumulator (host byte order,
 * one's complement partial sum).  Caller folds and applies to tcp->check.
 *
 * We scan at most 40 bytes of options (TCP max header is 60B, fixed hdr 20B).
 * The BPF verifier requires bounded loops; we unroll manually up to 10 options.
 */
static __always_inline __s32 rewrite_tcp_options(
    struct tcphdr *tcp,
    void          *data_end,
    __s32          ts_delta,
    __s32          ack_delta,
    int            is_egress)
{
    __u8 *opts = (__u8 *)tcp + 20; /* option bytes start after fixed 20B header */
    __u32 opts_len = (tcp->doff * 4) - 20;
    if (opts_len == 0)
        return 0;
    /* Clamp to verifier-acceptable bound. */
    if (opts_len > 40)
        opts_len = 40;

    __s32 csum_delta = 0;
    __u32 i = 0;

#pragma unroll
    for (int iter = 0; iter < 10; iter++) {
        if (i >= opts_len)
            break;
        if ((__u8 *)opts + i + 1 > (__u8 *)data_end)
            break;

        __u8 kind = opts[i];
        if (kind == TCPOPT_EOL)
            break;
        if (kind == TCPOPT_NOP) {
            i++;
            continue;
        }

        if ((__u8 *)opts + i + 2 > (__u8 *)data_end)
            break;
        __u8 len = opts[i + 1];
        if (len < 2)
            break;

        if (kind == TCPOPT_TS && len == 10) {
            if ((__u8 *)opts + i + 10 > (__u8 *)data_end)
                break;
            if (is_egress) {
                /* TSval is at offset +2 within the option. */
                __be32 *tsval = (__be32 *)(opts + i + 2);
                __be32 old = *tsval;
                *tsval = bpf_htonl(bpf_ntohl(old) + ts_delta);
                csum_delta += (bpf_ntohl(*tsval) - bpf_ntohl(old));
            } else {
                /* TSecr is at offset +6 within the option. */
                __be32 *tsecr = (__be32 *)(opts + i + 6);
                __be32 old = *tsecr;
                *tsecr = bpf_htonl(bpf_ntohl(old) + ts_delta);
                csum_delta += (bpf_ntohl(*tsecr) - bpf_ntohl(old));
            }
        } else if (kind == TCPOPT_SACK && len >= 10) {
            /* SACK blocks: each block is 8 bytes (left_edge + right_edge).
             * Max 4 blocks = 32 bytes + 2 header = 34 bytes. */
            __u8 num_blocks = (len - 2) / 8;
            if (num_blocks > 4)
                num_blocks = 4;
#pragma unroll
            for (int b = 0; b < 4; b++) {
                if (b >= num_blocks)
                    break;
                __u32 off = i + 2 + b * 8;
                if ((__u8 *)opts + off + 8 > (__u8 *)data_end)
                    break;
                __be32 *left  = (__be32 *)(opts + off);
                __be32 *right = (__be32 *)(opts + off + 4);
                __be32 old_l = *left;
                __be32 old_r = *right;
                *left  = bpf_htonl(bpf_ntohl(old_l) + ack_delta);
                *right = bpf_htonl(bpf_ntohl(old_r) + ack_delta);
                csum_delta += (bpf_ntohl(*left)  - bpf_ntohl(old_l));
                csum_delta += (bpf_ntohl(*right) - bpf_ntohl(old_r));
            }
        }

        i += len;
    }

    return csum_delta;
}

/* ── Egress relay ─────────────────────────────────────────────────────────── */

/*
 * pm_relay_tc_egress — TC egress on flannel.1 (outer direction, pod→peer).
 * Looks up the inner 4-tuple in PM_SEQ_XLAT; if found and active, applies
 * seq_delta/ack_delta/ts_delta and recomputes TCP + UDP checksums.
 * UDP checksum is zeroed per RFC 7348 §6 (VXLAN-in-UDP MAY zero it).
 */
SEC("tc")
int pm_relay_tc_egress(struct __sk_buff *skb)
{
    struct iphdr  *inner_ip;
    struct tcphdr *tcp;
    void          *data_end;

    if (parse_vxlan_inner_tcp(skb, &inner_ip, &tcp, &data_end) != 0)
        return TC_ACT_OK;

    struct four_tuple key = {
        .src_ip   = inner_ip->saddr,
        .dst_ip   = inner_ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    struct seq_xlat_entry *e = bpf_map_lookup_elem(&PM_SEQ_XLAT, &key);
    if (!e || e->state != 1)
        return TC_ACT_OK;

    /* Apply seq_delta to seq number. */
    __be32 old_seq = tcp->seq;
    tcp->seq = bpf_htonl(bpf_ntohl(old_seq) + e->seq_delta);
    tcp->check = csum_diff32(tcp->check, old_seq, tcp->seq);

    /* Apply ack_delta to ack number (only if ACK flag set). */
    if (tcp->ack) {
        __be32 old_ack = tcp->ack_seq;
        tcp->ack_seq = bpf_htonl(bpf_ntohl(old_ack) + e->ack_delta);
        tcp->check = csum_diff32(tcp->check, old_ack, tcp->ack_seq);
    }

    /* Rewrite TSval + SACK edges in TCP options. */
    if (e->ts_delta != 0 || e->sack_present) {
        __s32 opt_csum = rewrite_tcp_options(tcp, data_end, e->ts_delta, e->ack_delta, 1);
        if (opt_csum != 0) {
            /* Fold opt_csum into tcp->check incrementally. */
            __u32 c = (~bpf_ntohs(tcp->check)) & 0xffff;
            if (opt_csum > 0)
                c += (__u32)opt_csum;
            else
                c -= (__u32)(-opt_csum);
            c = (c >> 16) + (c & 0xffff);
            c += (c >> 16);
            tcp->check = bpf_htons((__u16)~c);
        }
    }

    /* Zero outer UDP checksum (RFC 7348 §6 permits this for VXLAN-in-UDP). */
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *outer_ip = (void *)(eth + 1);
    __u32 outer_ip_hlen = outer_ip->ihl * 4;
    struct udphdr *udp = (void *)outer_ip + outer_ip_hlen;
    if ((void *)(udp + 1) <= data_end)
        udp->check = 0;

    return TC_ACT_OK;
}

/* ── Ingress relay ────────────────────────────────────────────────────────── */

/*
 * pm_relay_tc_ingress — TC ingress on flannel.1 (incoming direction, peer→pod).
 * Mirror of egress but with reversed delta signs.
 * The 4-tuple lookup uses dst/src swapped (peer's seq is our ack and vice versa).
 */
SEC("tc")
int pm_relay_tc_ingress(struct __sk_buff *skb)
{
    struct iphdr  *inner_ip;
    struct tcphdr *tcp;
    void          *data_end;

    if (parse_vxlan_inner_tcp(skb, &inner_ip, &tcp, &data_end) != 0)
        return TC_ACT_OK;

    /* Ingress: swap src/dst to look up the local-side entry. */
    struct four_tuple key = {
        .src_ip   = inner_ip->daddr,
        .dst_ip   = inner_ip->saddr,
        .src_port = tcp->dest,
        .dst_port = tcp->source,
    };

    struct seq_xlat_entry *e = bpf_map_lookup_elem(&PM_SEQ_XLAT, &key);
    if (!e || e->state != 1)
        return TC_ACT_OK;

    /* Peer's seq is relative to the old destination — subtract seq_delta. */
    __be32 old_seq = tcp->seq;
    tcp->seq = bpf_htonl(bpf_ntohl(old_seq) - e->seq_delta);
    tcp->check = csum_diff32(tcp->check, old_seq, tcp->seq);

    /* Peer's ack acknowledges our (already shifted) seq — subtract ack_delta. */
    if (tcp->ack) {
        __be32 old_ack = tcp->ack_seq;
        tcp->ack_seq = bpf_htonl(bpf_ntohl(old_ack) - e->ack_delta);
        tcp->check = csum_diff32(tcp->check, old_ack, tcp->ack_seq);
    }

    /* TSecr must track what we sent them (TSval already shifted by +ts_delta),
     * so we un-apply the same ts_delta on the echo. */
    if (e->ts_delta != 0 || e->sack_present) {
        __s32 opt_csum = rewrite_tcp_options(tcp, data_end, e->ts_delta, e->ack_delta, 0);
        if (opt_csum != 0) {
            __u32 c = (~bpf_ntohs(tcp->check)) & 0xffff;
            if (opt_csum > 0)
                c += (__u32)opt_csum;
            else
                c -= (__u32)(-opt_csum);
            c = (c >> 16) + (c & 0xffff);
            c += (c >> 16);
            tcp->check = bpf_htons((__u16)~c);
        }
    }

    /* Zero outer UDP checksum. */
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *outer_ip = (void *)(eth + 1);
    __u32 outer_ip_hlen = outer_ip->ihl * 4;
    struct udphdr *udp = (void *)outer_ip + outer_ip_hlen;
    if ((void *)(udp + 1) <= data_end)
        udp->check = 0;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
