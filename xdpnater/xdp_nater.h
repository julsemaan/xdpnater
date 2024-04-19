//go:build ignore

#ifndef ROUTER_H
#define ROUTER_H
#include <linux/types.h>

// max # of vlan for trunked ports
#define MAX_TRUNK_VLANS 8

// max # of interfaces
#define MAX_IFACES 16

#define NATPORT_SIZE 4000
#define DRANGE_START 61000
#define DRANGE_SIZE 4500

struct stat_t {
  __u64 cnt;
  struct bpf_spin_lock lock;
};

struct l4pkt_t {
  __u8 protocol;
  __be32 saddr;
  __be32 daddr;
  __be16 source;
  __be16 dest;
};

struct dnat_t {
  __u8 protocol;
  __be32 addr;
  __be16 port;
  __u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NATPORT_SIZE);
    __type(key, struct dnat_t);
    __type(value, struct dnat_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} natportmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NATPORT_SIZE);
    __type(key, struct dnat_t);
    __type(value, struct dnat_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rev_natportmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NATPORT_SIZE);
    __type(key, struct dnat_t);
    __type(value, struct dnat_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} natportmap_dest SEC(".maps");

__u32 natip_config_index = 0;
__u32 natifindex_config_index = 1;
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_nater_conf SEC(".maps");

__u32 natportmap_tracker_index = 0;
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct stat_t);
} statmap SEC(".maps");

enum vlan_mode {
    VLAN_ACCESS = 0,
    VLAN_TRUNK = 1
};

struct if_vlan_info {
    // enum vlan_mode
    __u8 mode;

    // native vlan id (for both trunk and access)
    __be16 pvid;

    // trunked vlan id (for trunk)
    __be16 trunks[MAX_TRUNK_VLANS];
};

struct vlan_hdr {
    __be16	vlan_id;
    __be16	inner_ether_proto;
};

// helper: decr ttl by 1 for IP and IPv6
static __always_inline void _decr_ttl(__u16 proto, void *h) {
    if (proto == ETH_P_IP) {
        struct iphdr *ip = h;
        __u32 c = ip->check;
        c += bpf_htons(0x0100);
        ip->check = (__u16)(c + (c >= 0xffff));
        --ip->ttl;
    } else if (proto == ETH_P_IPV6) --((struct ipv6hdr*) h)->hop_limit;
}

static __always_inline void close_natport(struct dnat_t *rev_dnat_key) {
  struct dnat_t *val = bpf_map_lookup_elem(&rev_natportmap, rev_dnat_key);
  if(val == 0) {
    return;
  }
  val->ts = 0;
  bpf_map_delete_elem(&rev_natportmap, rev_dnat_key);
  bpf_map_delete_elem(&natportmap_dest, rev_dnat_key);
  bpf_map_delete_elem(&natportmap, val);

  struct stat_t *natportmap_tracker = bpf_map_lookup_elem(&statmap, &natportmap_tracker_index);
  if(natportmap_tracker != 0) {
    bpf_spin_lock(&natportmap_tracker->lock);
    natportmap_tracker->cnt--;
    bpf_spin_unlock(&natportmap_tracker->lock);
  }
}

static __always_inline __be16 calculate_natport(struct dnat_t *dnat_src, struct dnat_t *dnat_dest) {
  //return bpf_ntohs(bpf_get_prandom_u32() % 4000 + 61000);
  __be16 port = 0;
  
  __be16 drangeStart = DRANGE_START;
  __be16 drangeEnd = drangeStart+DRANGE_SIZE;
  __u64 ts = bpf_ktime_get_boot_ns();
  for (__be16 i = drangeStart; i <= drangeEnd; i++) {
    dnat_dest->port = bpf_ntohs(i);
    dnat_src->ts = ts;
    long rc = bpf_map_update_elem(&rev_natportmap, dnat_dest, dnat_src, BPF_NOEXIST);
    dnat_src->ts = 0;
    if(rc == 0) {
      port = dnat_dest->port;
      break;
    }
  }

  if(port == 0) {
    return port;
  }

  struct stat_t *natportmap_tracker = bpf_map_lookup_elem(&statmap, &natportmap_tracker_index);
  if(natportmap_tracker != 0) {
    bpf_spin_lock(&natportmap_tracker->lock);
    natportmap_tracker->cnt++;
    bpf_spin_unlock(&natportmap_tracker->lock);
  }
  else {
    // Don't necessarily care about concurrency in here. Worst case we can miss a few on startup, the cleanup loops should be able to tolerate this anyway.
    struct stat_t s = {};
    s.cnt = 1;
    bpf_map_update_elem(&statmap, &natportmap_tracker_index, &s, BPF_ANY);
  }
  
  long rc = bpf_map_update_elem(&natportmap, dnat_src, dnat_dest, BPF_ANY);
  if(rc != 0) {
    bpf_printk("Unable to update natportmap for a natport");
    return 0;
  }

  return port;
}

static __always_inline __sum16 csum_fold(__wsum csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__sum16)~csum;
}

static __always_inline __wsum csum_unfold(__sum16 csum)
{
	return (__wsum)csum;
}

static __always_inline __wsum csum_add(__wsum csum, __wsum addend)
{
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

static __always_inline void
__csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}


static __always_inline __wsum csum_diff(void *from, __u32 size_from,
					void *to,   __u32 size_to,
					__u32 seed)
{
	if (__builtin_constant_p(size_from) &&
	    __builtin_constant_p(size_to)) {
		/* Optimizations for frequent hot-path cases that are tiny to just
		 * inline into the code instead of calling more expensive helper.
		 */
		if (size_from == 4 && size_to == 4 &&
		    __builtin_constant_p(seed) && seed == 0)
			return csum_add(~(*(__u32 *)from), *(__u32 *)to);
		if (size_from == 4 && size_to == 4)
			return csum_add(seed,
					csum_add(~(*(__u32 *)from),
						 *(__u32 *)to));
	}

	return bpf_csum_diff(from, size_from, to, size_to, seed);
}


#endif // ROUTER_H
