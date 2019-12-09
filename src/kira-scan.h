#ifndef __KIRA_SCAN_H
#define __KIRA_SCAN_H 1

#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "xscan_sniffer.h"
#include "init.h"
#include "sleep.h"

#ifdef __cplusplus
extern "C" {
#endif

short  xscan_scan_host( struct xp_stats *stats, char *src_ip, char *dst_ip );
short  xscan_send_packet( short proto, char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port );
short  xscan_init_packet( int proto, char *src_ip, char *dst_ip, uint16_t sport, uint16_t dport );
short  xscan_push_host( xstate_t state, const char *ip, const SCPorts *ports );

double cpercent( double total, double frac );

void  xscan_print_stats( struct xp_stats *stats );
void  xscan_reset_stats( struct xp_stats *stats );
void  xscan_free_stats( struct xp_stats *stats );
void  xscan_accum_stats( struct xp_stats *stats );
void  __xscan_initiate__( struct xp_stats *stats );
void  __End__( int sig );

char * xscan_portstate_expl( port_t state );

#ifdef __cplusplus
}
#endif

#endif
