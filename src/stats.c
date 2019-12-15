#include "stats.h"

void xscan_print_hosts( struct xp_stats *stats )
{
    // list all the hosts that are down
    char *type;

    type = xsc_upper( stats->scanned_hosts[1].type );
    printf( "\n\t\t [%s]\n", type );
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

    type = xsc_upper( stats->scanned_hosts[0].type );
    printf( "\n\t\t  [%s]\n", type );
    if ( stats->nactive ) {
        for ( register uint16_t i = 0 ; i < stats->nactive ; i++ ) {
            v_out(
                VINF,
                "[%s]\n",
                stats->scanned_hosts[0].buffer[i]->ip
            );
            v_out(
                VINF,
                "Ports open     -> %d\n",
                stats->nopen
            );
            v_out(
                VINF,
                "Ports closed   -> %d\n",
                stats->nclosed
            );
            v_out(
                VINF,
                "Ports filtered -> %d\n",
                stats->nfiltered
            );
            v_ch( '\n' );

            xscan_print_ports(
                stats->scanned_hosts[0].buffer[i]->ports,
                stats->nports
            );
            v_ch( '\n' );
            v_ch( '\n' );
        }
    }
    if ( !stats->nactive ) {
        printf( "\t\t--NONE--\n\n" );
    }
    free( type );
}

void xscan_print_ports( SCPorts *ports, uint16_t nports )
{
    char *serv;
    char *state;
    
    printf( "\t[PORT]   [SERVICE]   [STATE]\n" );
    for ( register uint16_t i = 0 ; i < nports + 1 ; i++ )
    {
        // have we reached the last port ?
        if ( ports[i].port != 0 )
        {
            state = xscan_portstate_expl( ports[i].state );
            serv  = portservice( ports[i].port );
            printf( "\t%-8d %-11s %-10s\n", ports[i].port, serv, state );
        }
    }
    free( serv );
    free( state );
}

char * xscan_portstate_expl( port_t state )
{
    char *state_expl;

    state_expl = (char *) calloc( 10, sizeof( char ) );
    if ( !state_expl ) {
        return NULL;
    }
    
    switch ( state ) {
        case XCLOSED:
            strcpy( state_expl, "closed" );
            break;

        case XOPEN:
            strcpy( state_expl, "open" );
            break;

        default:
            strcpy( state_expl, "filtered" );
            break;
    }
    return state_expl;
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
