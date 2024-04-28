//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>

#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_nater.h"

char _license[] SEC("license") = "GPL";

// #define BPF_TRACE_NAT_CHECKS
#define BPF_TRACE_NAT_HITS

#define ICMP_PROCOTOL_ID 1
#define TCP_PROCOTOL_ID 6
#define UDP_PROCOTOL_ID 17

// main router logic
SEC("xdp") int xdp_nater(struct xdp_md *ctx) {
    struct __sk_buff *skb2 = (struct __sk_buff *)ctx;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    __be32 natip = 0;
    __be32 *config_natip = bpf_map_lookup_elem(&xdp_nater_conf, &natip_config_index);
    if(config_natip != 0) {
      natip = *config_natip;
    }
    else {
      bpf_printk("Invalid natip");
      return XDP_PASS;
    }

    __be32 natifindex = 0;
    __u8 valid_natifindex = 0;
    __be32 *config_natifindex = bpf_map_lookup_elem(&xdp_nater_conf, &natifindex_config_index);
    if(config_natifindex != 0) {
      natifindex = *config_natifindex;
      valid_natifindex = 1;
    }
    else {
      bpf_printk("Invalid natifindex");
      return XDP_PASS;
    }

    long rc;

    // invalid pkt: ethhdr overflow
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    // ptr to l3 protocol headers (or inner l2, if vlan)
    void *l3hdr = data + sizeof(struct ethhdr);

    // ethertype
    __u16 ether_proto = bpf_ntohs(eth->h_proto);

    // vlan header found, just strip it.
    if (ether_proto == ETH_P_8021Q || ether_proto == ETH_P_8021AD) {
        // tagged pkt on non-trunked port, drop
        struct vlan_hdr *vhdr = l3hdr;
        if (l3hdr + sizeof(struct vlan_hdr) > data_end) return XDP_DROP;
        
        l3hdr += sizeof(struct vlan_hdr);
        ether_proto = vhdr->inner_ether_proto;
    }

    if (ether_proto == ETH_P_IP) {
        struct bpf_fib_lookup fib_params = {};
        struct l4pkt_t l4pkt = {};
        __sum16 l3check;
        __sum16 l4check;
        __u8 closing = 0;

        if (l3hdr + sizeof(struct iphdr) > data_end) return XDP_DROP;
        struct iphdr *ip = l3hdr;

        if (ip->ttl <= 1) return XDP_PASS;

        l4pkt.protocol = ip->protocol;
        l4pkt.saddr = ip->saddr;
        l4pkt.daddr = ip->daddr;
        l3check = ip->check;
        
        __be16 natport;

        struct tcphdr *tcp;
        struct udphdr *udp;
        struct icmphdr *icmp;
        if(ip->protocol == ICMP_PROCOTOL_ID) {
          if (l3hdr + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) return XDP_DROP;
          icmp = l3hdr + sizeof(struct iphdr);
          l4pkt.source = icmp->un.echo.id;
          l4pkt.dest = icmp->un.echo.id;
          l4check = icmp->checksum;
          if(icmp->type == 0) {
            closing = 1;
          }
        }
        else if(ip->protocol == TCP_PROCOTOL_ID) {
          if (l3hdr + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) return XDP_DROP;
          tcp = l3hdr + sizeof(struct iphdr);
          l4pkt.source = tcp->source;
          l4pkt.dest = tcp->dest;
          l4check = tcp->check;
        }
        else if(ip->protocol == UDP_PROCOTOL_ID) {
          if (l3hdr + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) return XDP_DROP;
          udp = l3hdr + sizeof(struct iphdr);
          l4pkt.source = udp->source;
          l4pkt.dest = udp->dest;
          l4check = udp->check;
        }
        else {
          return XDP_PASS;
        }

        fib_params.family = AF_INET;
        fib_params.tos = ip->tos;
        fib_params.l4_protocol = ip->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(ip->tot_len);
        fib_params.ipv4_src = ip->saddr;
        fib_params.ipv4_dst = ip->daddr;
    
        fib_params.ifindex = ctx->ingress_ifindex;

        rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        
        struct dnat_t dnat_back_key = {};
        dnat_back_key.protocol = l4pkt.protocol;
        dnat_back_key.addr = l4pkt.saddr;
        dnat_back_key.port = l4pkt.dest;
        struct dnat_t *dnat_back_val = bpf_map_lookup_elem(&rev_natportmap, &dnat_back_key);
#ifdef BPF_TRACE_NAT_CHECKS
        bpf_printk("NAT check %pI4 %d", &dnat_back_key.addr, bpf_htons(dnat_back_key.port));
#endif
        if(l4pkt.daddr == natip && dnat_back_val != 0) {
#ifdef BPF_TRACE_NAT_HITS
          bpf_printk("NAT back %pI4 %pI4", &l4pkt.saddr, &l4pkt.daddr);
          bpf_printk("NAT back %d %d", bpf_htons(l4pkt.source), bpf_htons(l4pkt.dest));
#endif

          __u64 ts = bpf_ktime_get_boot_ns();

          dnat_back_val->ts = ts;
          long update_rc = bpf_map_update_elem(&rev_natportmap, &dnat_back_key, dnat_back_val, BPF_EXIST);
          dnat_back_val->ts = 0;
          if(update_rc != 0) {
            bpf_printk("Miss on NAT back in natportmap %pI4 %d", &dnat_back_key.addr, bpf_htons(dnat_back_key.port));
            return XDP_DROP;
          }
          
          __be32 old_ip = l4pkt.daddr;
          __be32 new_ip = dnat_back_val->addr;
          __be32 l3sum = 0;
          __wsum diff_ip = csum_diff(&old_ip, 4, &new_ip, 4, l3sum);

          __be32 old_port = l4pkt.dest;
          __be32 new_port = dnat_back_val->port;
          __be32 l4sum = 0;
          __wsum diff_port = csum_diff(&old_port, 4, &new_port, 4, l4sum);

          __sum16 sum = l3check;
          __csum_replace_by_diff(&sum, diff_ip);
          l3check = sum;

          sum = l4check;
          if(l4pkt.protocol == TCP_PROCOTOL_ID || l4pkt.protocol == UDP_PROCOTOL_ID) {
            __csum_replace_by_diff(&sum, diff_ip);
          }
          __csum_replace_by_diff(&sum, diff_port);
          l4check = sum;

          l4pkt.daddr = new_ip;
          l4pkt.dest = new_port;

          //ICMP flow always reads the echo ID from the source field
          if(l4pkt.protocol == ICMP_PROCOTOL_ID) {
            l4pkt.source = dnat_back_val->port;
          }
          
          fib_params.ipv4_src = l4pkt.saddr;
          fib_params.ipv4_dst = l4pkt.daddr;
          rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

          if(closing) {
            //bpf_printk("NAT BACK CLOSING NAT connection");
            close_natport(&dnat_back_key);
          }
        }
        else {
          fib_params.ipv4_src = l4pkt.saddr;
          fib_params.ipv4_dst = l4pkt.daddr;
          rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        
          if(rc == BPF_FIB_LKUP_RET_SUCCESS && valid_natifindex && fib_params.ifindex == natifindex) {
            struct dnat_t dnat_src = {};
            dnat_src.protocol = l4pkt.protocol;
            dnat_src.addr = l4pkt.saddr;
            dnat_src.port = l4pkt.source;

            struct dnat_t dnat_dest = {};
            struct dnat_t *existing_dnat_dest = bpf_map_lookup_elem(&natportmap, &dnat_src);

            if(existing_dnat_dest != 0) {
              dnat_dest = *existing_dnat_dest;
              natport = dnat_dest.port;
          
              __u64 ts = bpf_ktime_get_boot_ns();
          
              dnat_src.ts = ts;
              long update_rc = bpf_map_update_elem(&rev_natportmap, &dnat_dest, &dnat_src, BPF_EXIST);
              dnat_src.ts = 0;
              if(update_rc != 0) {
                bpf_printk("Miss on NAT reuse in natportmap %pI4 %d", &dnat_dest.addr, bpf_htons(dnat_dest.port));
                return XDP_DROP;
              }

#ifdef BPF_TRACE_NAT_HITS
              bpf_printk("NAT reuse %pI4 %pI4", &dnat_src.addr, &dnat_dest.addr);
              bpf_printk("NAT reuse %d %d", bpf_htons(dnat_src.port), bpf_htons(dnat_dest.port));
#endif
              if(closing) {
                //bpf_printk("NAT REUSE CLOSING NAT connection");
                close_natport(&dnat_dest);
              }
            }
            else {
              dnat_dest.protocol = l4pkt.protocol;
              dnat_dest.addr = l4pkt.daddr;

              natport = calculate_natport(&dnat_src, &dnat_dest);
              if(natport == 0) {
                bpf_printk("Dropping because out of natports");
                return XDP_DROP;
              }
              struct dnat_t dnat_orig_dest = {};
              dnat_orig_dest.protocol = l4pkt.protocol;
              dnat_orig_dest.addr = l4pkt.daddr;
              dnat_orig_dest.port = l4pkt.dest;
              bpf_map_update_elem(&natportmap_dest, &dnat_dest, &dnat_orig_dest, BPF_ANY);
#ifdef BPF_TRACE_NAT_HITS
              bpf_printk("NAT put %pI4 %pI4", &dnat_src.addr, &dnat_dest.addr);
              bpf_printk("NAT put %d %d", bpf_htons(dnat_src.port), bpf_htons(dnat_dest.port));
#endif
            }
          
            __be32 old_ip = l4pkt.saddr;
            __be32 new_ip = natip;
            __be32 l3sum = 0;
            __wsum diff_ip = csum_diff(&old_ip, 4, &new_ip, 4, l3sum);

            __be32 old_port = l4pkt.source;
            __be32 new_port = natport;
            __be32 l4sum = 0;
            __wsum diff_port = csum_diff(&old_port, 4, &new_port, 4, l4sum);

            __csum_replace_by_diff(&l3check, diff_ip);

            if(l4pkt.protocol == TCP_PROCOTOL_ID || l4pkt.protocol == UDP_PROCOTOL_ID) {
              __csum_replace_by_diff(&l4check, diff_ip);
            }
            __csum_replace_by_diff(&l4check, diff_port);

            l4pkt.saddr = natip;
            l4pkt.source = natport;
          }
          else {
            return XDP_PASS;
          }
        }

        switch(rc) {
            case BPF_FIB_LKUP_RET_SUCCESS:
                __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
                __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

                ip->saddr = l4pkt.saddr;
                ip->daddr = l4pkt.daddr;
                ip->check = l3check;
                if(ip->protocol == ICMP_PROCOTOL_ID) {
                  if (l3hdr + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) return XDP_DROP;
                  icmp = l3hdr + sizeof(struct iphdr);
                  icmp->un.echo.id = (__be16) l4pkt.source;  
                  icmp->checksum = l4check;
                }
                else if(ip->protocol == TCP_PROCOTOL_ID) {
                  if (l3hdr + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) return XDP_DROP;
                  tcp = l3hdr + sizeof(struct iphdr);
                  tcp->source = l4pkt.source;
                  tcp->dest = l4pkt.dest;
                  tcp->check = l4check;
                }
                else if(ip->protocol == UDP_PROCOTOL_ID) {
                  if (l3hdr + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) return XDP_DROP;
                  udp = l3hdr + sizeof(struct iphdr);
                  udp->source = l4pkt.source;
                  udp->dest = l4pkt.dest;
                  udp->check = l4check;
                } 

                _decr_ttl(ether_proto, l3hdr);
                return bpf_redirect(fib_params.ifindex, 0);
            case BPF_FIB_LKUP_RET_BLACKHOLE:
            case BPF_FIB_LKUP_RET_UNREACHABLE:
            case BPF_FIB_LKUP_RET_PROHIBIT:
                return XDP_DROP;
            case BPF_FIB_LKUP_RET_NOT_FWDED:
            case BPF_FIB_LKUP_RET_FWD_DISABLED:
            case BPF_FIB_LKUP_RET_UNSUPP_LWT:
            case BPF_FIB_LKUP_RET_NO_NEIGH:
            case BPF_FIB_LKUP_RET_FRAG_NEEDED:
                return XDP_PASS;
        }

    }

    return XDP_PASS;
}
