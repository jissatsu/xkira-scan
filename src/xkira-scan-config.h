#ifndef __KIRA_SCAN_SETUP_H
#define __KIRA_SCAN_SETUP_H 1

#include <stdint.h>
#include "packet/ipv4.h"
#include "packet/icmp.h"
#include "packet/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XSCAN_NBUFFERS 3

// receiver thread
// xkira-scan-config.h
pthread_t thread;

// xscan error buffer
// xkira-scan-config.h
char xscan_errbuf[0xFF];

static char *buffs[3] = {
    "up",
    "down",
    "filtered"
};

typedef enum { X_SYN, X_ICMP  } scan_t;
typedef enum { XDOWN, XACTIVE, XFILTERED } xstate_t;
typedef enum { XOPEN = 1, XCLOSED } port_t;

// xkira-scan-config.h
struct args
{
    char *type;
    char *host;
    char *ports;
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

/*
 * The current host that is in the scan
 */
typedef struct current_host
{
    char ip[17];
    short state;        /* state of the host (up or down) default is `0` (down) */
    short port_resp;    /* this is set to 1 if the host has sent atleast one RST (port is closed) or one ACK (port is open), 0 otherwise (all ports are filtered) assuming the host is up */
    SCPorts *ports;     /* the scan ports for the host */
}
__attribute__((packed)) SCHost;

/*
 * A buffer to hold all the scanned hosts
 */
typedef struct scanned_hosts
{
    char type[10];    /* buffer type (filtered, up, down) */
    char head[10];    /* buffer heading [FILTERED], [UP], [DOWN] */
    SCHost **buffer;  /* buffer */
}
__attribute__((packed)) SChosts;

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
    struct ports _ports;  /* ports to scan */
    struct host _host;    /* data associated with the host */
}
__attribute__((packed)) setup;

// xkira-scan-config.h
struct xp_stats
{
    uint16_t nhosts;        /* calculated hosts scan range from subnet */
    uint16_t nports;        /* total number of ports to scan */
    uint16_t ndown;         /* number of hosts that are down */
    uint16_t nfiltered;     /* number of hosts that have all scanned ports filtered */
    uint16_t nactive;       /* number of hosts that are active (those that have responded on atleast one port) */
    uint16_t nclosed;       /* number of closed ports */
    uint16_t nopen;         /* number of open ports */

    uint32_t scan_ip;       /* next ip address to scan */
    uint32_t nsent;         /* number of packets sent (used to calculate progress percentage) */
    uint32_t tpkts;         /* total number of packets to send (used to calculate progress percentage) */

    SChosts *scanned_hosts; /* a buffer containing all the scanned hosts with their associated ports */
    SCHost  current_host;   /* host currently in scan */

    double done;            /* progress percentage */
    double time;            /* time it took to perform the scan */
}
__attribute__((packed)) stats;

#ifdef __cplusplus
}
#endif

#endif