#ifndef __XKIRA_TCP_H
#define __XKIRA_TCP_H 1 

#include "include.h"
#include "../inline.h"

#ifdef __cplusplus
extern "C"{
#endif

struct tcp_flags
{
    uint8_t ns:2;
    uint8_t cwr:2;
    uint8_t ece:2;
    uint8_t urg:2;
    uint8_t ack:2;
    uint8_t psh:2;
    uint8_t rst:2;
    uint8_t syn:2;
    uint8_t fin:2;
}
tcp_flags;

struct tcphdr * xscan_build_tcp( struct tcp_flags flags, uint32_t src_port, uint32_t dst_port, char *sbuff );

#ifdef __cplusplus
}
#endif

#endif
