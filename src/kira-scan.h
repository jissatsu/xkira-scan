#ifndef __KIRA_SCAN_H
#define __KIRA_SCAN_H 1

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <libnet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAXWAIT 10
#define MAXKPACKET 4096

// xscan error buffer
char xscan_errbuf[0xFF];

typedef enum { X_SYN, X_ICMP } scan_t;
typedef enum { X_IP,  X_NM   } proto_t;

struct ports
{
    uint16_t start;       /* start port */
    uint16_t end;         /* end port (0 if no port range was specified) */
};

struct host
{
    char *name;           /* hostname */
    char *ip;             /* host ip */
};

struct xp_setup
{
    pid_t pid;            /* process id */
    short type;           /* scan type (icmp or syn) */
    short on;             /*  */
    short is_tty;
    short subnet;         /* subnet to scan */
    uint16_t nhosts;      /* calculated hosts scan range from subnet */
    uint32_t start;       /* start ip address (used only when subnet is set) */
    struct ports _ports;  /* ports to scan */
    struct host _host;    /* data associated with the host */
}
setup;

struct xp_stats
{
    uint16_t nrecv;       /* number of received replies */
    uint16_t nsent;       /* number of packets sent */
}
stats;

short   __xscan_init__( const char **argv, struct xp_setup *setup );
short   xscan_hstr_format( char *host );
short   xhost_info( char *host, struct xp_setup *setup );
void    __diE__( int sig );
void    xscan_init_packet( struct protoent *proto );

uint16_t * x_ports( char *ports );

#ifdef __cplusplus
}
#endif

#endif
