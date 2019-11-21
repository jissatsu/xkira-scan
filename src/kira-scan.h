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

short  xscan_start_sniffer( struct xp_stats *stats );
void   __xscan_initiate__( struct xp_stats *stats, void (*shandler)(struct xp_stats *stats) );
void   __End__( int sig );

struct xp_packet * xscan_init_packet( int proto, char *src_ip, char *dst_ip, struct ports *ports, char *sbuff );

#ifdef __cplusplus
}
#endif

#endif
