#ifndef __XKIRA_TCP_H
#define __XKIRA_TCP_H 1 

#include "include.h"
#include "../inline.h"

#ifdef __cplusplus
extern "C"{
#endif

struct tcp_flags
{
    uint8_t ns:1;
    uint8_t cwr:1;
    uint8_t ece:1;
    uint8_t urg:1;
    uint8_t ack:1;
    uint8_t psh:1;
    uint8_t rst:1;
    uint8_t syn:1;
    uint8_t fin:1;
};

struct tcphdr * xscan_build_tcp( struct tcp_flags flags, char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, char *data, char *sbuff );

#ifdef __cplusplus
}
#endif

#endif
