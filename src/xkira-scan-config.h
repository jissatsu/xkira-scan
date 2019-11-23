#ifndef __KIRA_SCAN_SETUP_H
#define __KIRA_SCAN_SETUP_H 1

#include <stdint.h>
#include "packet/ipv4.h"
#include "packet/icmp.h"
#include "packet/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

// xscan error buffer
// xkira-scan-config.h
char xscan_errbuf[0xFF];

typedef enum { X_SYN, X_ICMP } scan_t;

// xkira-scan-config.h
struct args
{
    char *iface;
    char *type;
    char *host;
    char *ports;
    int verbose;
}
__attribute__((packed));

struct ports
{
    short range;          /* 1 if port range 0 otherwise */
    uint32_t start;       /* start port */
    uint32_t end;         /* end port (0 if no port range was specified) */
};

struct host
{
    char *name;           /* hostname */
    char *ip;             /* host ip */
    short subnet;         /* subnet to scan */
};

// xscan config structure
// xkira-scan-config.h
struct xp_setup
{
    pid_t pid;            /* process id */
    char ip[30];          /* our ip address */
    short type;           /* scan type (icmp or syn) */
    short on;             /* range scan (scan a subnet or multiple ports) */
    short tty;
    int verbose;          /* verbose mode */
    struct ports _ports;  /* ports to scan */
    struct host _host;    /* data associated with the host */
}
__attribute__((packed)) setup;

// xkira-scan-config.h
struct xp_stats
{
    uint16_t nhosts;    /* calculated hosts scan range from subnet */
    uint16_t nports;    /* total number of ports to scan */
    uint32_t scan_ip;   /* next ip address to scan */
    uint32_t nrecv;     /* number of received replies */
    uint32_t nsent;     /* number of packets sent */
    uint32_t tpkts;     /* total number of packets to send */
    double time;        /* time it took to perform the scan */
}
__attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
