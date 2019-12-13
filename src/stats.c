#include "stats.h"

void xscan_print_hosts( struct xp_stats *stats )
{
    // list all the hosts that are down
    char *type;

    type = xsc_upper( stats->scanned_hosts[1].type );
    printf( "\n\t\t[%s]\n", type );
    if ( stats->ndown ) {
        for ( register uint16_t i = 0 ; i < stats->ndown ; i++ ) {
            v_out(
                VINF,
                "Host [%s] is down!\n",
                stats->scanned_hosts[1].buffer[i]->ip
            );
        }
        v_ch( '\n' );
        v_ch( '\n' );
    }
    if ( !stats->ndown ) {
        printf( "\t\t--NONE--\n\n" );
    }
    free( type );

    // list all the hosts that have the scan ports filtered
    type = xsc_upper( stats->scanned_hosts[2].type );
    printf( "\n\t\t[%s]\n", type );
    if ( stats->nfiltered ) {
        for ( register uint16_t i = 0 ; i < stats->nfiltered ; i++ ) {
            v_out(
                VINF,
                "Host [%s] has ports %d - %d filtered!\n",
                stats->scanned_hosts[2].buffer[i]->ip,
                setup._ports.start,
                setup._ports.end
            );
        }
        v_ch( '\n' );
        v_ch( '\n' );
    }
    if ( !stats->nfiltered ) {
        printf( "\t\t--NONE--\n\n" );
    }
    free( type );
}

void xscan_free_stats( struct xp_stats *stats )
{
    if ( stats->current_host.ports ) {
        free( stats->current_host.ports );
    }
    
    for ( register uint16_t i = 0 ; i < XSCAN_NBUFFERS ; i++ ) {
        if ( stats->scanned_hosts[i].buffer ) {
            free( stats->scanned_hosts[i].buffer );
        }
    }
    free( stats->scanned_hosts );
}

double cpercent( double total, double frac )
{
    return (double) (frac / total) * 100;
}
