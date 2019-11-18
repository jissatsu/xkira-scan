#ifndef __XKIRA_ICMP_H
#define __XKIRA_ICMP_H 1

#include "include.h"
#include "../inline.h"

#ifdef __cplusplus
extern "C"{
#endif

short xscan_build_icmp( uint16_t type, pid_t pid, uint16_t cksum, char *sbuff );

#ifdef __cplusplus
}
#endif

#endif
