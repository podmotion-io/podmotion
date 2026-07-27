// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
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
 *       SACK block left/right edges += seq_delta  (edges are in OUR send-seq space)
 *
 *   pm_relay_tc_ingress — attached to flannel.1 TC ingress (incoming direction).
 *     Incoming means: peer → pod.  We apply the NEGATIVE delta:
 *       seq  -= seq_delta   (peer thinks it is talking to old socket)
 *       ack  -= ack_delta
 *       TSecr += ts_delta   (peer's echo of our TSval; must be shifted the same way)
 *       SACK edges -= seq_delta  (same sequence space; undo the egress shift)
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
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ── PM_SEQ_XLAT map ──────────────────────────────────────────────────────── */

/*
 * FourTuple — network-byte-order 4-tuple used as PM_SEQ_XLAT map key.
 * src/dst are from the inner TCP segment's perspective.
 *
 * IPv4 ONLY (ADR-0081): src_ip and dst_ip are 32-bit IPv4 addresses (__be32).
 * An IPv6 address is 128 bits; IPv6 source addresses cause silent truncation or
 * mismatch on this key. IPv6 extension point (for M25/ADR-0081 implementor):
 *
 *   Replace __be32 src_ip/__be32 dst_ip with:
 *     union { __be32 v4; __be32 v6[4]; } src_ip;
 *     union { __be32 v4; __be32 v6[4]; } dst_ip;
 *     __u8 family;   // AF_INET or AF_INET6
 *     __u8 _pad[3];
 *
 *   Also add parse_ipv6_hdr() XDP parsing path and explicit XDP_PASS for
 *   ICMPv6 types 133-137 (NDP Neighbor Solicitation/Advertisement) so NDP
 *   frames are not dropped when the XDP program is attached.
 *
 *   The PM_SEQ_XLAT map max_entries and map_flags do not change; only
 *   sizeof(struct four_tuple) changes, which __type(key, ...) picks up.
 *
 * Track IPv6 support: https://github.com/podmotion-io/podmotion/issues/IPv6
 */
struct four_tuple {
    __be32 src_ip;   /* IPv4 source address — ADR-0081: IPv4-only in v0.1/v0.2 */
    __be32 dst_ip;   /* IPv4 destination address — ADR-0081: IPv4-only in v0.1/v0.2 */
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
 *
 * The running sum is carried as a __u32 to accommodate the range
 * [0, 3*0xffff] during accumulation.  Two fold passes are required to
 * handle the case where the first fold still leaves a carry in bit 16
 * (e.g. when the subtracted old_val produces an underflow that the single
 * (sum>>16)+(sum&0xffff) pass does not fully absorb).  The second pass
 * guarantees the result fits in 16 bits (RFC 1624 §3).
 */
static __always_inline __sum16 csum_diff32(__sum16 old_csum, __be32 old_val, __be32 new_val)
{
    __u32 csum = (~bpf_ntohs(old_csum)) & 0xffff;
    csum -= (bpf_ntohl(old_val) >> 16);
    csum -= (bpf_ntohl(old_val) & 0xffff);
    csum += (bpf_ntohl(new_val) >> 16);
    csum += (bpf_ntohl(new_val) & 0xffff);
    /* Two fold passes: the first may still leave a carry in bit 16. */
    csum = (csum >> 16) + (csum & 0xffff);
    csum = (csum >> 16) + (csum & 0xffff);
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
/*
 * ADR-0403 D1 (load-corrected): __noinline, and returns byte OFFSETS from
 * skb->data — NOT packet pointers.
 *
 * Two coupled reasons:
 *  1. off=14 hoist: under __always_inline the LLVM BPF backend hoists the
 *     guarded outer_ip->ihl read (:160) above its own bounds check (:154) and
 *     CSE-merges it with the epilogue's duplicate read, producing off=14.
 *     A BPF-to-BPF call keeps that read in the callee frame, guarded first.
 *  2. But a __noinline callee CANNOT hand a packet pointer back to its caller:
 *     a pkt pointer spilled into the caller frame is reloaded as an opaque
 *     scalar, and the caller's first dereference rejects with
 *     "R1 invalid mem access 'scalar'". Scalars survive the call boundary, so
 *     the helper returns bounded offsets (inner IP, inner TCP, outer UDP) and
 *     each caller re-derives the pointer from a fresh skb->data with its own
 *     > data_end bounds check after a constant offset clamp (see PM_MAX_*_OFF).
 * The epilogue outer-UDP re-derivation (below) uses out_outer_udp_off and no
 * longer re-reads outer_ip->ihl — removing the duplicate read that fed the CSE
 * merge. Both TC programs load-proven on kernel 6.8.0-136-generic; see
 * docs/proof/PM-RELAY-CODEGEN-INVESTIGATION.md and ADR-0403 §P-VERIFY RESULTS.
 */
static __noinline int parse_vxlan_inner_tcp(
    struct __sk_buff *skb,
    __u32            *out_inner_ip_off,
    __u32            *out_tcp_off,
    __u32            *out_outer_udp_off)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return TC_ACT_OK;

    if (outer_ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u32 outer_ip_hlen = outer_ip->ihl * 4;
    struct udphdr *udp = (void *)outer_ip + outer_ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(udp->dest) != VXLAN_UDP_PORT)
        return TC_ACT_OK;

    /* Skip VXLAN header (8 bytes) + inner Ethernet header. */
    void *vxlan_inner_eth = (void *)(udp + 1) + VXLAN_HDR_LEN;
    struct ethhdr *inner_eth = vxlan_inner_eth;
    if ((void *)(inner_eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(inner_eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return TC_ACT_OK;

    if (inner_ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 inner_ip_hlen = inner_ip->ihl * 4;
    struct tcphdr *tcp = (void *)inner_ip + inner_ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    *out_inner_ip_off  = (__u32)((__u8 *)inner_ip - (__u8 *)data);
    *out_tcp_off       = (__u32)((__u8 *)tcp      - (__u8 *)data);
    *out_outer_udp_off = (__u32)((__u8 *)udp      - (__u8 *)data);
    return 0;
}

/* Upper bounds (compile-time constants) for the offsets the parse helper returns,
 * so each re-derived caller pointer carries a tight umax for the verifier. Outer
 * IP ≤ 60, inner IP ≤ 60; the deepest header (inner TCP) sits at
 * 14+60+8+8+14+60 = 164 < 192. */
#define PM_MAX_INNER_IP_OFF  128u
#define PM_MAX_TCP_OFF       192u
#define PM_MAX_OUTER_UDP_OFF 80u

/* ── TCP option rewriting ─────────────────────────────────────────────────── */

#define TCPOPT_EOL   0
#define TCPOPT_NOP   1
#define TCPOPT_MSS   2
#define TCPOPT_WSCALE 3
#define TCPOPT_SACK_PERM 4
#define TCPOPT_SACK  5
#define TCPOPT_TS    8

/*
 * opt_csum_add32: accumulate the one's-complement checksum difference for a
 * 32-bit field change.  A 32-bit value covers two 16-bit checksum words;
 * they must each contribute independently so that a carry out of the low
 * half is not silently lost.  Using a plain arithmetic delta (new32-old32)
 * on a 32-bit accumulator is WRONG when the low 16 bits carry into the high
 * half (e.g. old=0x0000FFFF, new=0x00010001: delta=2 but the high-half word
 * changed by +1 and the low-half word changed by +2, giving an independent
 * sum of 3, not 2).
 *
 * The running sum is __u32 to hold up to 4*0xffff without wrapping.
 */
static __always_inline __u32 opt_csum_add32(__u32 csum_acc, __be32 old_val, __be32 new_val)
{
    __u32 old_h = bpf_ntohl(old_val) >> 16;
    __u32 old_l = bpf_ntohl(old_val) & 0xffff;
    __u32 new_h = bpf_ntohl(new_val) >> 16;
    __u32 new_l = bpf_ntohl(new_val) & 0xffff;
    /* Subtract old halves, add new halves.  Carry is accumulated in the upper
     * bits and folded by the caller. */
    csum_acc += new_h - old_h + new_l - old_l;
    return csum_acc;
}

/*
 * rewrite_tcp_options: scan TCP options and patch TSval (egress) or TSecr
 * (ingress) and SACK block edges.
 *
 * is_egress==1  → patch TSval field (+ts_delta) + SACK edges (+seq_delta)
 * is_egress==0  → patch TSecr field (+ts_delta) + SACK edges (-seq_delta)
 *
 * SACK edge correction:
 *   Egress (pod→peer): SACK blocks contain sequence numbers in OUR send
 *   space, which has been shifted by seq_delta.  Edges must be shifted by
 *   +seq_delta (same sign as the seq rewrite).
 *
 *   Ingress (peer→pod): SACK blocks in a packet from the peer acknowledge
 *   segments in OUR send space.  The peer saw seq numbers that already had
 *   +seq_delta applied; to undo that for the local socket we apply -seq_delta.
 *   Using ack_delta here was WRONG (different sequence space, possibly
 *   different magnitude and sign).
 *
 * Returns the accumulated one's-complement checksum delta for all rewritten
 * option fields (running __u32 partial sum, caller must fold and apply to
 * tcp->check using the same csum_diff32 approach).
 *
 * We scan at most 40 bytes of options (TCP max header is 60B, fixed hdr 20B).
 * The BPF verifier requires bounded loops; we unroll manually up to 10 options.
 */
static __always_inline __u32 rewrite_tcp_options(
    struct tcphdr *tcp,
    void          *data_end,
    __s32          ts_delta,
    __s32          seq_delta,
    int            is_egress)
{
    __u8 *opts = (__u8 *)tcp + 20; /* option bytes start after fixed 20B header */
    __u32 opts_len = (tcp->doff * 4) - 20;
    if (opts_len == 0)
        return 0;
    /* Clamp to verifier-acceptable bound. */
    if (opts_len > 40)
        opts_len = 40;

    /* sack_edge_delta: +seq_delta on egress, -seq_delta on ingress.
     * This correctly adjusts SACK block edges relative to OUR send-sequence
     * space in both directions (see function comment above). */
    __s32 sack_edge_delta = is_egress ? seq_delta : -seq_delta;

    __u32 csum_acc = 0; /* accumulated one's-complement partial sum */

    /*
     * ADR-0403 D2: cursor-POINTER scan (was integer-index scan). Advance a single
     * packet pointer `cur`, and guard every read on the exact register it
     * dereferences. The prior form re-materialized `opts + i` at each access from
     * an integer `i` whose only re-narrowing was a lossy reg-vs-reg `i >= opts_len`
     * compare plus a data_end compare on an accumulating value (`len` is an
     * unbounded-above packet byte). The verifier could not carry the proven range
     * across the separately re-derived read pointer and rejected at off=64 with the
     * index scalar widened to [33..286]. Advancing a pointer keeps the accessible-
     * range fact attached to the register that is read. All rewrite arithmetic
     * below (ts_delta, sack_edge_delta, opt_csum_add32) is byte-for-byte identical
     * to the index form; only the addressing changes. See
     * docs/proof/PM-RELAY-CODEGEN-INVESTIGATION.md.
     */
    __u8 *cur      = opts;
    __u8 *opts_end = opts + opts_len; /* logical end of options region */

#pragma unroll
    for (int iter = 0; iter < 10; iter++) {
        /* kind byte — guard the exact cursor we read. */
        if (cur + 1 > opts_end)
            break;
        if (cur + 1 > (__u8 *)data_end)
            break;

        __u8 kind = cur[0];
        if (kind == TCPOPT_EOL)
            break;
        if (kind == TCPOPT_NOP) {
            cur += 1;
            continue;
        }

        /* length byte. */
        if (cur + 2 > (__u8 *)data_end)
            break;
        __u8 len = cur[1];
        if (len < 2)
            break;

        if (kind == TCPOPT_TS && len == 10) {
            if (cur + 10 > (__u8 *)data_end)
                break;
            if (is_egress) {
                /* TSval is at offset +2 within the option. */
                __be32 *tsval = (__be32 *)(cur + 2);
                __be32 old = *tsval;
                *tsval = bpf_htonl(bpf_ntohl(old) + ts_delta);
                csum_acc = opt_csum_add32(csum_acc, old, *tsval);
            } else {
                /* TSecr is at offset +6 within the option. */
                __be32 *tsecr = (__be32 *)(cur + 6);
                __be32 old = *tsecr;
                *tsecr = bpf_htonl(bpf_ntohl(old) + ts_delta);
                csum_acc = opt_csum_add32(csum_acc, old, *tsecr);
            }
        } else if (kind == TCPOPT_SACK && len >= 10) {
            /* SACK blocks: each block is 8 bytes (left_edge + right_edge).
             * Max 4 blocks = 32 bytes + 2 header = 34 bytes. */
            __u8 num_blocks = (len - 2) / 8;
            if (num_blocks > 4)
                num_blocks = 4;
            __u8 *blk = cur + 2; /* first block; advanced by a POINTER below */
#pragma unroll
            for (int b = 0; b < 4; b++) {
                if (b >= num_blocks)
                    break;
                /* Guard the exact block pointer we read (8 bytes: 2×__be32). */
                if (blk + 8 > (__u8 *)data_end)
                    break;
                __be32 *left  = (__be32 *)blk;
                __be32 *right = (__be32 *)(blk + 4);
                __be32 old_l = *left;
                __be32 old_r = *right;
                *left  = bpf_htonl(bpf_ntohl(old_l) + sack_edge_delta);
                *right = bpf_htonl(bpf_ntohl(old_r) + sack_edge_delta);
                csum_acc = opt_csum_add32(csum_acc, old_l, *left);
                csum_acc = opt_csum_add32(csum_acc, old_r, *right);
                blk += 8;
            }
        }

        cur += len;
    }

    return csum_acc;
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
    __u32 inner_ip_off = 0, tcp_off = 0, outer_udp_off = 0;
    if (parse_vxlan_inner_tcp(skb, &inner_ip_off, &tcp_off, &outer_udp_off) != 0)
        return TC_ACT_OK;

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Re-derive inner IP / TCP from the helper's scalar offsets with fresh
     * bounds checks (offsets survive the __noinline call; packet pointers do not). */
    if (inner_ip_off > PM_MAX_INNER_IP_OFF || tcp_off > PM_MAX_TCP_OFF)
        return TC_ACT_OK;
    struct iphdr *inner_ip = data + inner_ip_off;
    if ((void *)(inner_ip + 1) > data_end)
        return TC_ACT_OK;
    struct tcphdr *tcp = data + tcp_off;
    if ((void *)(tcp + 1) > data_end)
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
        __u32 opt_csum = rewrite_tcp_options(tcp, data_end, e->ts_delta, e->seq_delta, 1);
        if (opt_csum != 0) {
            /* Fold opt_csum (one's-complement partial sum) into tcp->check.
             * Start from the one's complement of the existing checksum, add
             * the accumulated delta, then two-fold to absorb any carry.      */
            __u32 c = (~bpf_ntohs(tcp->check)) & 0xffff;
            c += opt_csum;
            c = (c >> 16) + (c & 0xffff);
            c = (c >> 16) + (c & 0xffff);
            tcp->check = bpf_htons((__u16)~c);
        }
    }

    /* Zero outer UDP checksum (RFC 7348 §6 permits this for VXLAN-in-UDP).
     * Re-derive the outer UDP header from the helper's offset; no re-read of
     * outer_ip->ihl here (that duplicate read is what CSE-merged and hoisted). */
    if (outer_udp_off <= PM_MAX_OUTER_UDP_OFF) {
        struct udphdr *udp = data + outer_udp_off;
        if ((void *)(udp + 1) <= data_end)
            udp->check = 0;
    }

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
    __u32 inner_ip_off = 0, tcp_off = 0, outer_udp_off = 0;
    if (parse_vxlan_inner_tcp(skb, &inner_ip_off, &tcp_off, &outer_udp_off) != 0)
        return TC_ACT_OK;

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Re-derive inner IP / TCP from the helper's scalar offsets with fresh
     * bounds checks (offsets survive the __noinline call; packet pointers do not). */
    if (inner_ip_off > PM_MAX_INNER_IP_OFF || tcp_off > PM_MAX_TCP_OFF)
        return TC_ACT_OK;
    struct iphdr *inner_ip = data + inner_ip_off;
    if ((void *)(inner_ip + 1) > data_end)
        return TC_ACT_OK;
    struct tcphdr *tcp = data + tcp_off;
    if ((void *)(tcp + 1) > data_end)
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
     * so we un-apply the same ts_delta on the echo.
     * SACK edges on ingress reference OUR send-sequence space; rewrite_tcp_options
     * with is_egress=0 applies -seq_delta to each edge (correct sign). */
    if (e->ts_delta != 0 || e->sack_present) {
        __u32 opt_csum = rewrite_tcp_options(tcp, data_end, e->ts_delta, e->seq_delta, 0);
        if (opt_csum != 0) {
            __u32 c = (~bpf_ntohs(tcp->check)) & 0xffff;
            c += opt_csum;
            c = (c >> 16) + (c & 0xffff);
            c = (c >> 16) + (c & 0xffff);
            tcp->check = bpf_htons((__u16)~c);
        }
    }

    /* Zero outer UDP checksum. Re-derive from the helper's offset. */
    if (outer_udp_off <= PM_MAX_OUTER_UDP_OFF) {
        struct udphdr *udp = data + outer_udp_off;
        if ((void *)(udp + 1) <= data_end)
            udp->check = 0;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
