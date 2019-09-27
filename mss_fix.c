#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdint.h>
#include <netinet/in.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inine
# define __inline			  \
    inline __attribute__((always_inline))
#endif

static __inline uint16_t csum16_add(uint16_t csum, uint16_t addend){
    uint16_t res = csum;
    res += addend;
    return (uint16_t)(res + (res < addend));
}

static __inline uint16_t csum16_sub(uint16_t csum, uint16_t addend){
    return csum16_add(csum, ~addend);
}

static __inline void csum_replace2(uint16_t *sum, uint16_t old, uint16_t new){
*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}



__section("prog")
int xdp_main(struct xdp_md *ctx)
{
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;

    struct ethhdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    uint8_t *tcp_opts;
    eth_hdr = (struct ethhdr *) data;
    if ((uint8_t *)eth_hdr + sizeof(struct ethhdr) > (uint8_t *) data_end)
        return XDP_DROP;
    if (eth_hdr->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    ip_hdr = (struct iphdr *) ((uint8_t *)data + sizeof(struct ethhdr));
    if ((uint8_t *)ip_hdr + sizeof(struct iphdr) > (uint8_t *) data_end)
        return XDP_DROP;
    if (ip_hdr->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp_hdr = (struct tcphdr *) ((uint8_t *)data
                                 + sizeof(struct ethhdr) + ip_hdr->ihl * 4);

    if ((uint8_t *)tcp_hdr + sizeof(struct tcphdr) > (uint8_t *)data_end)
        return XDP_DROP;

    if (tcp_hdr->syn) {
        tcp_opts = (uint8_t *)data + sizeof(struct ethhdr)
                   + ip_hdr->ihl * 4 + sizeof(struct tcphdr);
        uint8_t i, kind, tmp_size;
        uint16_t * mss = 0;
        uint16_t old_mss;
        #pragma clang loop unroll(enable)
        for (i = 0; i < 40; i++){
            if(tcp_opts + 4 <= (uint8_t *)data_end){
                tmp_size = 1;
                if (tcp_opts <= (uint8_t *)data_end){
                    kind = *(tcp_opts);
                }
                if (kind == 0){
                    return XDP_PASS;
                }
                if (kind == 1){
                    if(tcp_opts + 1 <= (uint8_t *)data_end){
                        tmp_size = *(tcp_opts + 1);
                    }
                }
                if (kind == 2){
                    if (tcp_opts + 4 <= (uint8_t *)data_end){
                        mss = (uint16_t *)(tcp_opts + 2);
                        old_mss = *mss;
                        *mss = __constant_htons(1400);
                        csum_replace2(&tcp_hdr->check, old_mss, *mss);
                        return XDP_PASS;
                    }
                }
                tcp_opts += tmp_size;
            }
        }
    }
    return XDP_PASS;
}

char __license[] __section("license") = "GPL";