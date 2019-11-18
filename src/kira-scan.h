#ifndef __KIRA_SCAN_H
#define __KIRA_SCAN_H 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <getopt.h>
#include "output/output.h"
#include "inline.h"
#include "xkira-scan-config.h"
#include "xscan_sniffer.h"
#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { X_SYN, X_ICMP } scan_t;

// kira-scan.h
struct args
{
    char *iface;
    char *type;
    char *host;
    char *ports;
    int verbose;
}
__attribute__((packed));

// packet structure
// kira-scan.h
struct xp_packet
{
    struct icmp *icmp;   /* icmp header */
    struct ip *ip;       /* ipv4 header */
    struct tcphdr *tcp;  /* tcp  header */
};

short  __xscan_init__( struct args *args, struct xp_setup *setup );
short  xscan_start_sniffer( struct xp_stats *stats );
short  xscan_hostinfo( char *host, struct xp_setup *setup );
short  xscan_set_ports( const char *p, struct ports *ports );
short  xscan_validate_ports( struct ports *ports );

void   __xscan_initiate__( struct xp_stats *stats, void (*shandler)(struct xp_stats *stats) );
void   __End__( int sig );

struct args * xscan_parse_options( int argc, char **argv, void (*usage)(char *) );

#ifdef __cplusplus
}
#endif

#endif
