#include "stats.h"

void xscan_print_hosts( struct xp_stats *stats )
{
    printf( "[DOWN]\n" );
    if ( stats->ndown ) {
        for ( register uint16_t i = 0 ; i < stats->ndown ; i++ ) {
            printf( "%s\n", stats->buffers[1].buffer[i] );
        }
        v_ch( '\n' );
        v_ch( '\n' );
    }

    printf( "[FILTERED]\n" );
    if ( stats->nfiltered ) {
        for ( register uint16_t i = 0 ; i < stats->nfiltered ; i++ ) {
            printf( "%s\n", stats->buffers[2].buffer[i] );
        }
        v_ch( '\n' );
        v_ch( '\n' );
    }
    return;
}

double cpercent( double total, double frac )
{
    return (double) (frac / total) * 100;
}

void xscan_free_stats( struct xp_stats *stats )
{
    free( stats->scanned_ports );
    free( stats->hosts );

    for ( register uint16_t i = 0 ; i < XSCAN_NBUFFERS ; i++ ) {
        if ( stats->buffers[i].buffer ) {
            free( stats->buffers[i].buffer );
        }
    }
    free( stats->buffers );
}