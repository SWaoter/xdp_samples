#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdint.h>
#include <netinet/in.h>
#include <iproute2/bpf_elf.h>
#include <malloc.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
static void *BPF_FUNC(map_update_elem, void *map, const void *key, const void *value, uint64_t flags);

static struct bpf_elf_map counter __section("maps") = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .size_key       = sizeof(uint32_t),
    .size_value     = sizeof(uint32_t),
    .max_elem       = 6,
};


__section("prog")
int xdp_prog(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;

    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    eth_hdr = (struct ethhdr *) data;
    if ((uint8_t *)eth_hdr + sizeof(struct ethhdr) > (uint8_t *) data_end)
        return XDP_DROP;
    if (eth_hdr->h_proto != __constant_htons(ETH_P_IP) && eth_hdr->h_proto != __constant_htons(ETH_P_IPV6)){
		uint32_t tmp = 0;
		uint32_t * value = map_lookup_elem(&counter, &tmp);
		if(value != 0){
			uint32_t * new_value = (uint32_t *)malloc(sizeof(uint32_t));
			*new_value = *value + 1;
			map_update_elem(&counter, &tmp, &new_value, 0);
			free(new_value);
		}
	   return XDP_PASS;
	}
    ip_hdr = (struct iphdr *) ((uint8_t *)data + sizeof(struct ethhdr));
    if ((uint8_t *)ip_hdr + sizeof(struct iphdr) > (uint8_t *) data_end)
        return XDP_DROP;
    if (ip_hdr->protocol == IPPROTO_TCP){
		uint32_t tmp;
		if(eth_hdr->h_proto == __constant_htons(ETH_P_IP)){
			tmp = 1;
		} else {
			tmp = 2;
		}
		uint32_t * value = map_lookup_elem(&counter, &tmp);
		if(value != 0){
			uint32_t * new_value = (uint32_t *)malloc(sizeof(uint32_t));
			*new_value = *value + 1;
			map_update_elem(&counter, &tmp, &new_value, 0);
			free(new_value);
		}
	   return XDP_PASS;
	}

	if (ip_hdr->protocol == IPPROTO_UDP){
		uint32_t tmp;
		if(eth_hdr->h_proto == __constant_htons(ETH_P_IP)){
			tmp = 3;
		} else {
			tmp = 4;
		}
		uint32_t * value = map_lookup_elem(&counter, &tmp);
		if(value != 0){
			uint32_t * new_value = (uint32_t *)malloc(sizeof(uint32_t));
			*new_value = *value + 1;
			map_update_elem(&counter, &tmp, &new_value, 0);
			free(new_value);
		}
	   return XDP_PASS;
	}
	return XDP_PASS;
}

char __license[] __section("license") = "GPL";