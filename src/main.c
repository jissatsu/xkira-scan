#include "kira-scan.h"

static void __usage( char *prog )
{
    printf( "Usage: %s\n", prog );
    printf( "-i [Interface name]\n" );
    printf( "-t [Scan type]\n" );
    printf( "-d [Destination address]\n" );
    printf( "-p [Port or Port range]\n" );
    exit( 1 );
}

static void display_stats( struct xp_stats *stats )
{
    ;
}

int main( int argc, char **argv )
{
    short init;
    struct xp_stats stats;

    struct args *args = xscan_parse_options(
        argc, argv, &__usage
    );
    
    init = __xscan_init__( args, &setup );
    if ( init != 0 ) {
        __die(
            "Xkira-scan initialization failed: %s\n", xscan_errbuf
        );
    }

    if ( xscan_start_sniffer( &stats ) < 0 ) {
        __die(
            "Xkira-scan sniffer failure: %s\n", xscan_errbuf
        );
    }
    #ifdef DEBUG
        printf( "[Debug]\n" );
        printf( "%s: Spawned scan sniffer!\n\n", __FILE__ );
    #endif

    // `setup.on` means we are not performing a single scan
    // we are either scanning a subnet or a single host on a port range
    if ( setup.on ) {
        signal( SIGINT,  __End__ );
        signal( SIGTERM, __End__ );
        #ifdef DEBUG
            printf( "[Debug]\n" );
            printf( "%s: Registered signal handler!\n\n", __FILE__ );
        #endif
    }

    __xscan_initiate__( &stats, &display_stats );
    exit( 0 );
}