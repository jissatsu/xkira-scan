#ifndef __XKIRA_IPV4_H
#define __XKIRA_IPV4_H 1 

#include "include.h"
#include "../inline.h"

#ifdef __cplusplus
extern "C"{
#endif

struct ip * xscan_build_ipv4( int proto, pid_t pid, const char *src_ip, const char *dst_ip, uint16_t cksum, char *sbuff );

#ifdef __cplusplus
}
#endif

#endif
