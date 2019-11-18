#ifndef __XSCAN_SNIFFER_H
#define __XSCAN_SNIFFER_H 1

#include <pcap.h>
#include "xkira-scan-config.h"

#ifdef __cplusplus
extern "C" {
#endif

void * scan_sniffer( void *st );

#ifdef __cplusplus
}
#endif

#endif