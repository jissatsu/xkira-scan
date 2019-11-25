#include "kira-scan.h"

static void __usage( char *prog )
{
    printf( "Usage: %s\n", prog );
    printf( "-t [Scan type]\n" );
    printf( "-d [Destination address]\n" );
    printf( "-p [Port or Port range]\n" );
    exit( 1 );
}

int main( int argc, char **argv )
{
    short init;
    int opt;
    struct args args;
    struct xp_stats stats;
    
    args.host  = NULL;
    args.ports = NULL;
    args.type  = NULL;
    args.verbose = 0;

    while ( (opt = getopt( argc, argv, "t:d:p:v" )) != -1 ) {
        switch ( opt ) {
            case 't':
                args.type  = optarg;
                break;
            case 'd':
                args.host  = optarg;
                break;
            case 'p':
                args.ports = optarg;
                break;
            case 'v':
                args.verbose = 1;
                break;
            default:
                __usage( argv[0] );
        }
    }

    if ( !args.host || !args.type ) {
        __usage( argv[0] );
    }
    
    init = __xscan_init__( &args, &stats, &setup );
    if ( init != 0 ) {
        __die( "Xkira-scan initialization failed: %s\n", xscan_errbuf );
    }

    if ( xscan_start_sniffer( &stats ) < 0 ) {
        __die( "Xkira-scan sniffer failure: %s\n", xscan_errbuf );
    }
    #ifdef DEBUG
        v_out( VDEBUG, "%s: %s", __FILE__, "Spawned scan sniffer!\n" );
    #endif

    // `setup.on` means we are not performing a single scan
    // we are either scanning a subnet or a single host on a port range
    if ( setup.on ) {
        //signal( SIGINT,  __End__ );
        //signal( SIGTERM, __End__ );
        #ifdef DEBUG
            v_out( VDEBUG, "%s: %s", __FILE__, "Registered signal handler!\n" );
        #endif
    }

    __xscan_initiate__( &stats );
    exit( 0 );
}