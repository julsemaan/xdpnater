//go:build ignore

#ifndef ROUTER_H
#define ROUTER_H
#include <linux/types.h>

// max # of vlan for trunked ports
#define MAX_TRUNK_VLANS 8

// max # of interfaces
#define MAX_IFACES 16

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
