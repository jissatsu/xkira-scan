#include "kira-scan.h"

void __usage( char *prog )
{
    printf( "Usage: %s [scan type] [hostname/ip] [port or port-range]\n", prog );
}

int main( int argc, char **argv )
{
    struct xp_setup setup;
    struct protoent *proto;

    if ( argc != 4 ) {
        __usage( argv[0] );
    }

    if ( __xscan_init__( (const char **) argv, &setup ) < 0 ){
        printf( "%s\n", xscan_errbuf );
        __usage( argv[0] );
    }

    switch ( setup.type ) {
        case X_SYN:
            proto = getprotobyname( "tcp" );
            break;
        case X_ICMP:
            proto = getprotobyname( "icmp" );
            break;
    }

    if ( setup.on ) {
        signal( SIGINT,  __diE__ );
        signal( SIGTERM, __diE__ );
    }
    return 0;
}