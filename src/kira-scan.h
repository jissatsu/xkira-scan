#ifndef __KIRA_SCAN_H
#define __KIRA_SCAN_H 1

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>       /* IPV4 */
#include <netinet/tcp.h>      /* SYN */
#include <netinet/ip_icmp.h>  /* ICMP */

#ifdef __cplusplus
extern "C" {
#endif

#define MAXWAIT 10
#define MAXKPACKET 4096

// xscan error buffer
char xscan_errbuf[0xFF];

typedef enum { X_SYN, X_ICMP } scan_t;
struct ports
{
    uint16_t start;
    uint16_t end;  /* 0 if no port range was specified */
};

struct host
{
    char *name;
    char *ip;
};

struct xp_setup
{
    pid_t pid;
    short type;
    short on;
    char *host;
    struct ports _ports;
    struct host _host;
};

struct xp_net
{
    short subnet;
    uint16_t nhosts;
    uint32_t start;
};

short   __xscan_init__( const char **argv, struct xp_setup *setup );
short   is_ip_format( char *host );
void    __diE__( int sig );
void    xhost_info( char host, struct xp_setup *setup );

uint16_t k_cksum( uint16_t *buff, int size );

#ifdef __cplusplus
}
#endif

#endif