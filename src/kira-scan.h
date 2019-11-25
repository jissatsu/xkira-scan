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

// packet structure
// kira-scan.h
struct xp_packet
{
    struct icmp *icmp;   /* icmp header */
    struct ip *ip;       /* ipv4 header */
    struct tcphdr *tcp;  /* tcp  header */
};

short  xscan_scan_host( int *sock, struct xp_stats *stats, char *src_ip, char *dst_ip );
short  xscan_start_sniffer( struct xp_stats *stats );
short  xscan_send_packet( int *sock, const void *buff, size_t size );
short  xscan_icmp( int *sock, struct host *host, struct xp_stats *stats );
short  xscan_syn( int *sock, struct host *host, struct ports *ports, struct xp_stats *stats );
void   __init_stats__( struct xp_stats *stats );
void   __xscan_initiate__( struct xp_stats *stats );
void   __End__( int sig );

struct xp_packet * xscan_init_packet( int proto, char *src_ip, char *dst_ip, uint16_t sport, uint16_t dport, char *sbuff );

#ifdef __cplusplus
}
#endif

#endif
