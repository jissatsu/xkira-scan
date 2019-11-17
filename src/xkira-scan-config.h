#ifndef __KIRA_SCAN_SETUP_H
#define __KIRA_SCAN_SETUP_H 1

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#ifdef __cplusplus
extern "C" {
#endif

// xscan error buffer
// xkira-scan-config.h
char xscan_errbuf[0xFF];

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
    short type;           /* scan type (icmp or syn) */
    short on;             /* range scan (scan a subnet or multiple ports) */
    short tty;
    int verbose;          /* verbose mode */
    uint16_t nhosts;      /* calculated hosts scan range from subnet */
    uint32_t start;       /* start ip address (used only when subnet is set) */
    struct ports _ports;  /* ports to scan */
    struct host _host;    /* data associated with the host */
}
__attribute__((packed)) setup;

// xkira-scan-config.h
struct xp_stats
{
    uint16_t nrecv;     /* number of received replies */
    uint16_t nsent;     /* number of packets sent */
    uint16_t tpkts;     /* total number of packets to send */
    double time;        /* time it took to perform the scan */
}
__attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
