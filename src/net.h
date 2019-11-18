#ifndef __KIRA_NET_H
#define __KIRA_NET_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include "xkira-scan-config.h"

#ifdef __cplusplus
extern "C" {
#endif

void  sockopt_hdrincl( int *sock, int *hdrincl );
short net_ip( const char *iface, char *dst );
char * is_ip( const char *str );

#ifdef __cplusplus
}
#endif

#endif