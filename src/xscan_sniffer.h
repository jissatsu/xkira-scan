#ifndef __XSCAN_SNIFFER_H
#define __XSCAN_SNIFFER_H 1

#include <pcap.h>
#include "output/output.h"
#include "xkira-scan-config.h"

#ifdef __cplusplus
extern "C" {
#endif

void packet_handler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void * scan_sniffer( void *st );

#ifdef __cplusplus
}
#endif

#endif