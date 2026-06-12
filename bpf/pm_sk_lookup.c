// SPDX-License-Identifier: GPL-2.0
/*
 * pm_sk_lookup.c — BPF_PROG_TYPE_SK_LOOKUP program.
 *
 * Steers incoming segments for migrated 4-tuples to the fresh destination
 * socket that was opened by the relay tier after CRIU restore in the
 * migration netns.
 *
 * When the relay tier opens a fresh socket bound to <source_ip>:<source_port>
 * toward the same peer, the kernel's normal socket lookup would not find a
 * listening socket in the initial netns.  This program runs in the
 * destination pod's netns and overrides the lookup for any 4-tuple present
 * in PM_SK_REDIRECT_MAP, selecting the pre-registered socket fd.
 *
 * Map: PM_SK_REDIRECT_MAP — BPF_MAP_TYPE_SOCKHASH keyed by four_tuple.
 * The agent inserts the fresh socket's fd before ZeroWindowDisarm.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct four_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 4096);
    __type(key, struct four_tuple);
    __type(value, __u64); /* socket cookie */
} PM_SK_REDIRECT_MAP SEC(".maps");

/*
 * pm_sk_lookup: called by the kernel for each incoming packet that needs a
 * socket.  If the packet's 4-tuple is in PM_SK_REDIRECT_MAP we redirect to
 * the registered socket; otherwise the kernel falls through to its normal
 * lookup.
 */
SEC("sk_lookup")
int pm_sk_lookup(struct bpf_sk_lookup *ctx)
{
    struct four_tuple key = {
        .src_ip   = ctx->remote_ip4,
        .dst_ip   = ctx->local_ip4,
        .src_port = bpf_htons(ctx->remote_port),
        .dst_port = bpf_htons((__u16)ctx->local_port),
    };

    struct bpf_sock *sk = bpf_map_lookup_elem(&PM_SK_REDIRECT_MAP, &key);
    if (!sk)
        return SK_PASS;

    long ret = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return ret == 0 ? SK_PASS : SK_DROP;
}

char _license[] SEC("license") = "GPL";
