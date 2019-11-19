#ifndef __XKIRA_TCP_H
#define __XKIRA_TCP_H 1 

#include "include.h"
#include "../inline.h"

#ifdef __cplusplus
extern "C"{
#endif

struct tcphdr * xscan_build_tcp( char *flags, uint32_t src_port, uint32_t dst_port, char *sbuff );

#ifdef __cplusplus
}
#endif

#endif
