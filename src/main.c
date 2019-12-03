#include "kira-scan.h"
#include "banner.h"

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
    
    args.host    = NULL;
    args.ports   = NULL;
    args.type    = NULL;
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

    xscan_banner();
    if ( !args.host || !args.type ) {
        __usage( argv[0] );
    }
    
    init = __xscan_init__( &args, &stats );
    if ( init != 0 ) {
        __die( "Xkira-scan initialization failed: %s\n", xscan_errbuf );
    }

    if ( xscan_start_receiver( &stats ) < 0 ) {
        __die( "Xkira-scan sniffer failure: %s\n", xscan_errbuf );
    }

    // wait for the sniffer to load fully, then initiate the scan
    mssleep( 0.5 );
    __xscan_initiate__( &stats );
    // wait for the receiver to terminate
    //pthread_join( thread, NULL );
    xscan_free_stats( &stats );
    exit( 0 );
}