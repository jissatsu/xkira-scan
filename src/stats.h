#ifndef __KIRA_STATS_H
#define __KIRA_STATS_H 1

#include <stdio.h>
#include "libs/xscan_str.h"
#include "output/output.h"
#include "xkira-scan-config.h"
#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

void  xscan_print_hosts( struct xp_stats *stats );
void  xscan_print_ports( SCPorts *ports, uint16_t nports );
void  xscan_free_stats( struct xp_stats *stats );

double cpercent( double total, double frac );

char * xscan_portstate_expl( port_t state );

#ifdef __cplusplus
}
#endif

#endif