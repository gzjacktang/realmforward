// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* XDP IPv4 DNAT+SNAT forward — no fragments, no IPv6 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef BPF_FIB_LOOKUP_DIRECT
#define BPF_FIB_LOOKUP_DIRECT (1U << 0)
#endif

/* Pin classic helper ID 189 so CI Ubuntu headers cannot emit unresolved kfunc. */
static long (*const xfp_xdp_load_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *)189;
#define bpf_xdp_load_bytes xfp_xdp_load_bytes

#define MAX_RULES 256
#define MAX_CT    65536

/* csum_mode: 0 = fast (default, incremental when check!=0), 1 = safe (full TCP recompute) */
#define CSUM_MODE_FAST 0
#define CSUM_MODE_SAFE 1

struct rule_key {
	__u16 dport;
	__u8  proto;
	__u8  pad;
};

struct rule_val {
	__u32 rule_id;
	__u32 dest_ip;
	__u16 dest_port;
	__u8  enabled;
	__u8  pad;
};

struct ct_key {
	__u32 ip;
	__u16 port;
	__u8  proto;
	__u8  dir;
};

struct ct_val {
	__u32 client_ip;
	__u32 dest_ip;
	__u16 client_port;
	__u16 local_port;
	__u16 dest_port;
	__u16 snat_port;
	__u32 rule_id;
};

struct stats_val {
	__u64 packets;
	__u64 bytes;
};

struct config_val {
	__u32 ifindex;
	__u32 local_ip;
	__u16 snat_min;
	__u16 snat_max;
	__u8  gw_mac[6];
	__u8  local_mac[6];
	__u8  has_gw;
	__u8  csum_mode;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, struct rule_key);
	__type(value, struct rule_val);
} rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_CT);
	__type(key, struct ct_key);
	__type(value, struct ct_val);
} conntrack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct stats_val);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config_val);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[1504]);
} scratch SEC(".maps");

/* Fold like kernel csum_fold(). */
static __always_inline __sum16 csum_fold_helper(__wsum csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__sum16)~csum;
}

/*
 * RFC1624 incremental update in host-numeric space (ntohs/htons).
 * Do NOT bpf_csum_diff stack __be32 on LE — spilled bytes are swapped vs wire.
 */
static __always_inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
{
	__u32 sum32 = ~(__u32)bpf_ntohs(*(__be16 *)sum) & 0xffff;
	sum32 += (~bpf_ntohl(from) & 0xffff) + (~(bpf_ntohl(from) >> 16) & 0xffff);
	sum32 += (bpf_ntohl(to) & 0xffff) + ((bpf_ntohl(to) >> 16) & 0xffff);
	sum32 = (sum32 & 0xffff) + (sum32 >> 16);
	sum32 = (sum32 & 0xffff) + (sum32 >> 16);
	*(__be16 *)sum = bpf_htons(~sum32 & 0xffff);
}

static __always_inline void csum_replace2(__sum16 *sum, __be16 from, __be16 to)
{
	__u32 sum32 = ~(__u32)bpf_ntohs(*(__be16 *)sum) & 0xffff;
	sum32 += (~bpf_ntohs(from) & 0xffff);
	sum32 += (bpf_ntohs(to) & 0xffff);
	sum32 = (sum32 & 0xffff) + (sum32 >> 16);
	sum32 = (sum32 & 0xffff) + (sum32 >> 16);
	*(__be16 *)sum = bpf_htons(~sum32 & 0xffff);
}

/* Full TCP/UDP recompute via scratch (verifier-safe). Used for virtio / NEEDS_CSUM. */
static __always_inline void recompute_ipv4_l4(struct xdp_md *ctx, struct iphdr *iph,
					     __sum16 *csum_field, __u8 proto)
{
	__u32 tot = bpf_ntohs(iph->tot_len);
	if (tot < sizeof(*iph))
		return;
	__u32 l4_len = tot - sizeof(*iph);
	if (l4_len < 8 || l4_len > 1480)
		return;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
	__u8 *l4 = (__u8 *)data + l4_off;
	if (l4 >= (__u8 *)data_end)
		return;
	__u32 avail = (__u32)((__u8 *)data_end - l4);
	if (l4_len > avail)
		return; /* refuse partial recompute — safer than wrong csum */

	__u32 zero = 0;
	__u8 *buf = bpf_map_lookup_elem(&scratch, &zero);
	if (!buf)
		return;
	if (bpf_xdp_load_bytes(ctx, l4_off, buf, l4_len) < 0)
		return;

	if (proto == IPPROTO_TCP && l4_len >= 18) {
		buf[16] = 0;
		buf[17] = 0;
	} else if (proto == IPPROTO_UDP && l4_len >= 8) {
		buf[6] = 0;
		buf[7] = 0;
	}

	__u32 rounded = (l4_len + 3) & ~3u;
	if (rounded > 1480)
		rounded = 1480;
	if (rounded > l4_len) {
		buf[l4_len] = 0;
		if (l4_len + 1 < 1480)
			buf[l4_len + 1] = 0;
		if (l4_len + 2 < 1480)
			buf[l4_len + 2] = 0;
	}

	/* Pseudo-header from packet memory (wire order) + proto/len bytes. */
	__wsum csum = bpf_csum_diff(NULL, 0, &iph->saddr, 8, 0);
	__u8 plen[4] = { 0, proto, (__u8)(l4_len >> 8), (__u8)l4_len };
	csum = bpf_csum_diff(NULL, 0, (__be32 *)plen, 4, csum);

	__u32 off = 0;
#pragma unroll
	for (int i = 0; i < 23; i++) {
		if (off + 64 > rounded)
			break;
		csum = bpf_csum_diff(NULL, 0, (__be32 *)(buf + off), 64, csum);
		off += 64;
	}
	if (off + 32 <= rounded) {
		csum = bpf_csum_diff(NULL, 0, (__be32 *)(buf + off), 32, csum);
		off += 32;
	}
	if (off + 16 <= rounded) {
		csum = bpf_csum_diff(NULL, 0, (__be32 *)(buf + off), 16, csum);
		off += 16;
	}
	if (off + 8 <= rounded) {
		csum = bpf_csum_diff(NULL, 0, (__be32 *)(buf + off), 8, csum);
		off += 8;
	}
	if (off + 4 <= rounded)
		csum = bpf_csum_diff(NULL, 0, (__be32 *)(buf + off), 4, csum);

	__sum16 folded = csum_fold_helper(csum);
	if (proto == IPPROTO_UDP && folded == 0)
		folded = (__sum16)0xffff;
	*csum_field = folded;
}

/*
 * Fast (default): incremental when check!=0; full recompute only for NEEDS_CSUM (0).
 * Safe: always full TCP recompute (virtio stale non-zero check workaround).
 * is_return kept for call sites; WAN return already covered by fast path.
 */
static __always_inline void apply_l4_csum(struct xdp_md *ctx, struct iphdr *iph,
					 __sum16 *check, __u8 proto, __u8 csum_mode,
					 __u8 is_return,
					 __be32 old_s, __be32 new_s,
					 __be32 old_d, __be32 new_d,
					 __be16 old_sp, __be16 new_sp,
					 __be16 old_dp, __be16 new_dp)
{
	if (proto == IPPROTO_UDP && *check == 0)
		return;

	if (proto == IPPROTO_TCP) {
		if (csum_mode != CSUM_MODE_SAFE && *check != 0) {
			csum_replace2(check, old_sp, new_sp);
			csum_replace2(check, old_dp, new_dp);
			csum_replace4(check, old_s, new_s);
			csum_replace4(check, old_d, new_d);
			return;
		}
		/* SAFE mode, or check==0 (NEEDS_CSUM): full recompute */
		(void)is_return;
		recompute_ipv4_l4(ctx, iph, check, proto);
		return;
	}

	csum_replace2(check, old_sp, new_sp);
	csum_replace2(check, old_dp, new_dp);
	csum_replace4(check, old_s, new_s);
	csum_replace4(check, old_d, new_d);
}

static __always_inline void bump_stats(__u32 rule_id, __u64 bytes)
{
	struct stats_val *st = bpf_map_lookup_elem(&stats, &rule_id);
	if (st) {
		/* Non-atomic: stats are informational; atomics cost pps on hot path. */
		st->packets += 1;
		st->bytes += bytes;
	} else {
		struct stats_val init = {.packets = 1, .bytes = bytes};
		bpf_map_update_elem(&stats, &rule_id, &init, BPF_ANY);
	}
}

static __always_inline int xdp_fib_tx(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph)
{
	__u32 zero = 0;
	struct config_val *cfg = bpf_map_lookup_elem(&config, &zero);

	/* Typical single-NIC VPS: all remote backends via default GW — skip FIB. */
	if (cfg && cfg->has_gw) {
		__builtin_memcpy(eth->h_dest, cfg->gw_mac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, cfg->local_mac, ETH_ALEN);
		return XDP_TX;
	}

	struct bpf_fib_lookup fib = {};
	fib.family = AF_INET;
	fib.tos = iph->tos;
	fib.l4_protocol = iph->protocol;
	fib.tot_len = bpf_ntohs(iph->tot_len);
	fib.ipv4_src = iph->saddr;
	fib.ipv4_dst = iph->daddr;
	fib.ifindex = ctx->ingress_ifindex;

	int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);

	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
		if (fib.ifindex == ctx->ingress_ifindex)
			return XDP_TX;
		return bpf_redirect(fib.ifindex, 0);
	}
	return XDP_PASS;
}

static __always_inline __u16 pick_snat(__u32 client_ip, __u16 client_port, __u16 local_port,
				      __u8 proto, __u16 snat_min, __u16 snat_max)
{
	__u32 span = (__u32)(snat_max - snat_min) + 1;
	if (span == 0)
		span = 1;
	__u32 h = client_ip ^ ((__u32)client_port << 16) ^ local_port ^ proto;
	h ^= h >> 16;
	return snat_min + (__u16)(h % span);
}

SEC("xdp")
int xdp_forward(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if (iph->ihl != 5)
		return XDP_PASS;
	if (iph->frag_off & bpf_htons(IP_MF | 0x1fff))
		return XDP_PASS;

	__u8 proto = iph->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return XDP_PASS;

	__be16 *ports = (void *)(iph + 1);
	if ((void *)(ports + 2) > data_end)
		return XDP_PASS;
	__u16 sport = bpf_ntohs(ports[0]);
	__u16 dport = bpf_ntohs(ports[1]);

	__u32 zero = 0;
	struct config_val *cfg = bpf_map_lookup_elem(&config, &zero);
	__u16 snat_min = 40000, snat_max = 49999;
	__u8 csum_mode = CSUM_MODE_SAFE;
	if (cfg) {
		snat_min = cfg->snat_min;
		snat_max = cfg->snat_max;
		csum_mode = cfg->csum_mode;
	}

	__u64 pkt_len = (__u64)(data_end - data);

	/* Return path */
	{
		struct ct_key ck = {
			.ip = iph->daddr,
			.port = dport,
			.proto = proto,
			.dir = 0,
		};
		struct ct_val *ct = bpf_map_lookup_elem(&conntrack, &ck);
		if (ct) {
			__be32 old_s = iph->saddr;
			__be32 old_d = iph->daddr;
			__be16 old_sp = ports[0];
			__be16 old_dp = ports[1];
			__be32 new_s = old_d;
			__be32 new_d = ct->client_ip;
			__be16 new_sp = bpf_htons(ct->local_port);
			__be16 new_dp = bpf_htons(ct->client_port);

			if (proto == IPPROTO_TCP) {
				struct tcphdr *tcp = (void *)(iph + 1);
				if ((void *)(tcp + 1) > data_end)
					return XDP_PASS;
				tcp->source = new_sp;
				tcp->dest = new_dp;
				csum_replace4(&iph->check, old_s, new_s);
				csum_replace4(&iph->check, old_d, new_d);
				iph->saddr = new_s;
				iph->daddr = new_d;
				apply_l4_csum(ctx, iph, &tcp->check, proto, csum_mode, 1,
					      old_s, new_s, old_d, new_d, old_sp, new_sp, old_dp, new_dp);
			} else {
				struct udphdr *udp = (void *)(iph + 1);
				if ((void *)(udp + 1) > data_end)
					return XDP_PASS;
				udp->source = new_sp;
				udp->dest = new_dp;
				csum_replace4(&iph->check, old_s, new_s);
				csum_replace4(&iph->check, old_d, new_d);
				iph->saddr = new_s;
				iph->daddr = new_d;
				apply_l4_csum(ctx, iph, &udp->check, proto, csum_mode, 1,
					      old_s, new_s, old_d, new_d, old_sp, new_sp, old_dp, new_dp);
			}

			bump_stats(ct->rule_id, pkt_len);
			return xdp_fib_tx(ctx, eth, iph);
		}
	}

	/* Forward path */
	struct rule_key rk = {.dport = dport, .proto = proto, .pad = 0};
	struct rule_val *rv = bpf_map_lookup_elem(&rules, &rk);
	if (!rv || !rv->enabled)
		return XDP_PASS;

	__u16 snat = pick_snat(iph->saddr, sport, dport, proto, snat_min, snat_max);

	/* Map dest_ip is big-endian numeric from userspace; convert once for wire. */
	__be32 dest_be = bpf_htonl(rv->dest_ip);

	struct ct_val cv = {
		.client_ip = iph->saddr,
		.dest_ip = dest_be,
		.client_port = sport,
		.local_port = dport,
		.dest_port = rv->dest_port,
		.snat_port = snat,
		.rule_id = rv->rule_id,
	};
	struct ct_key ck = {
		.ip = iph->daddr,
		.port = snat,
		.proto = proto,
		.dir = 0,
	};
	bpf_map_update_elem(&conntrack, &ck, &cv, BPF_ANY);

	__be32 old_s = iph->saddr;
	__be32 old_d = iph->daddr;
	__be16 old_sp = ports[0];
	__be16 old_dp = ports[1];
	__be32 new_s = old_d;
	__be32 new_d = dest_be;
	__be16 new_sp = bpf_htons(snat);
	__be16 new_dp = bpf_htons(rv->dest_port);

	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)(iph + 1);
		if ((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		tcp->source = new_sp;
		tcp->dest = new_dp;
		csum_replace4(&iph->check, old_s, new_s);
		csum_replace4(&iph->check, old_d, new_d);
		iph->saddr = new_s;
		iph->daddr = new_d;
		apply_l4_csum(ctx, iph, &tcp->check, proto, csum_mode, 0,
			      old_s, new_s, old_d, new_d, old_sp, new_sp, old_dp, new_dp);
	} else {
		struct udphdr *udp = (void *)(iph + 1);
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		udp->source = new_sp;
		udp->dest = new_dp;
		csum_replace4(&iph->check, old_s, new_s);
		csum_replace4(&iph->check, old_d, new_d);
		iph->saddr = new_s;
		iph->daddr = new_d;
		apply_l4_csum(ctx, iph, &udp->check, proto, csum_mode, 0,
			      old_s, new_s, old_d, new_d, old_sp, new_sp, old_dp, new_dp);
	}

	bump_stats(rv->rule_id, pkt_len);
	return xdp_fib_tx(ctx, eth, iph);
}

char _license[] SEC("license") = "Dual BSD/GPL";
