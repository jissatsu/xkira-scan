#ifndef __XSCAN_SNIFFER_H
#define __XSCAN_SNIFFER_H 1

#include <pcap.h>
#include <pthread.h>
#include "output/output.h"
#include "xkira-scan-config.h"

#ifdef __cplusplus
extern "C" {
#endif

short is_scan_port( uint16_t port );
short is_scan_host( char *ip, struct xp_stats *stats );
short xscan_start_receiver( struct xp_stats *stats );

void  xscan_set_portresp( char *ip, SCHosts *hosts, uint16_t nhosts );
void  xscan_add_port( uint16_t port, port_t state, SCPorts *ports, uint16_t nports );
void  packet_handler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void * scan_sniffer( void *st );

#ifdef __cplusplus
}
#endif

#endif