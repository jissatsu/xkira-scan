#include "tcp.h"

struct tcphdr * xscan_build_tcp( struct tcp_flags flags, uint32_t src_port, uint32_t dst_port, char *sbuff )
{
    static struct tcphdr *tcp;

    tcp = (struct tcphdr *) &sbuff[IPV4_H_SIZE];
    return tcp;
}