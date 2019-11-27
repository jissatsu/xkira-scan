#ifndef __KIRA_SCAN_H
#define __KIRA_SCAN_H 1

#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "xscan_sniffer.h"
#include "init.h"
#include "sleep.h"

#ifdef __cplusplus
extern "C" {
#endif

short  xscan_scan_host( struct xp_stats *stats, char *src_ip, char *dst_ip );
short  xscan_start_receiver( struct xp_stats *stats );
short  xscan_send_packet( const void *buff, size_t size );
short  xscan_init_packet( int proto, char *src_ip, char *dst_ip, uint16_t sport, uint16_t dport, char *sbuff );
short   __init_stats__( struct xp_stats *stats );

void   __xscan_initiate__( struct xp_stats *stats );
void   __End__( int sig );

#ifdef __cplusplus
}
#endif

#endif
