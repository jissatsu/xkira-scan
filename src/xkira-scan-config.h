#ifndef __KIRA_SCAN_SETUP_H
#define __KIRA_SCAN_SETUP_H 1

#include <stdint.h>
#include "packet/ipv4.h"
#include "packet/icmp.h"
#include "packet/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

// receiver thread
// xkira-scan-config.h
pthread_t thread;

// xscan error buffer
// xkira-scan-config.h
char xscan_errbuf[0xFF];

typedef enum { X_SYN, X_ICMP  } scan_t;
typedef enum { XOPEN = 1, XCLOSED } port_t;

// xkira-scan-config.h
struct args
{
    char *type;
    char *host;
    char *ports;
    short verbose;
}
__attribute__((packed));

struct ports
{
    short range;     /* 1 if port range 0 otherwise */
    uint32_t start;  /* start port */
    uint32_t end;    /* end port (0 if no port range was specified) */
};

struct host
{
    char *name;     /* hostname */
    char *ip;       /* host ip */
    short subnet;   /* subnet to scan */
};

typedef struct scanned_ports
{
    uint16_t port;
    short state;
}
__attribute__((packed)) SCPorts;

typedef struct scan_hosts
{
    char ip[17];
    uint32_t id;
}
__attribute__((packed)) SCHosts;

// xscan config structure
// xkira-scan-config.h
struct xp_setup
{
    pid_t pid;            /* process id */
    char ip[15];          /* our ip address */
    char iface[50];       /* our interface name */
    short type;           /* scan type (icmp or syn) */
    short on;             /* range scan (scan a subnet or multiple ports) */
    short tty;
    short verbose;        /* verbose mode */
    struct ports _ports;  /* ports to scan */
    struct host _host;    /* data associated with the host */
}
__attribute__((packed)) setup;

// xkira-scan-config.h
struct xp_stats
{
    uint16_t nhosts;        /* calculated hosts scan range from subnet */
    uint16_t nports;        /* total number of ports to scan */
    uint16_t nclosed;       /* number of closed ports */
    uint16_t nopen;         /* number of open ports */
    uint16_t nfiltered;     /* number of filtered ports */
    uint32_t scan_ip;       /* next ip address to scan */
    uint32_t nsent;         /* number of packets sent */
    uint32_t tpkts;         /* total number of packets to send */
    SCHosts *hosts;         /* a list of the hosts to scan */
    SCPorts *scanned_ports; /* scanned ports on target host (scan_ip) */
    char *current_host;     /* host currently in scan */
    double done;            /*  */
    double time;            /* time it took to perform the scan */
}
__attribute__((packed)) stats;

#ifdef __cplusplus
}
#endif

#endif