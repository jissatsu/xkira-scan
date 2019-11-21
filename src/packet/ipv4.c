#include "ipv4.h"

struct ip * xscan_build_ipv4( int proto, pid_t pid, const char *src_ip, const char *dst_ip, uint16_t csum, char *sbuff )
{
    struct in_addr src, dst;
    static struct ip *ipv4;

    ipv4 = (struct ip *) sbuff;

    ipv4->ip_hl  = 5;
    ipv4->ip_v   = 4;
    ipv4->ip_tos = 0;
    ipv4->ip_len = htons( IPV4_H_SIZE + ICMP_SIZE );
    ipv4->ip_id  = htons( pid );
    ipv4->ip_off = 0;
    ipv4->ip_ttl = 255;
    ipv4->ip_p   = proto;
    ipv4->ip_sum = 0;

    src.s_addr = inet_addr( src_ip );
    dst.s_addr = inet_addr( dst_ip );

    ipv4->ip_src = src;
    ipv4->ip_dst = dst;

    if ( csum < 0 ) {
        ipv4->ip_sum = k_cksum( (uint16_t *) ipv4, IPV4_H_SIZE );
    } else {
        ipv4->ip_sum = csum;
    }

    return ipv4;
}
