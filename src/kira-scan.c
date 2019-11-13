#include "inline.h"
#include "kira-scan.h"

short __xscan_init__( const char **argv, struct xp_setup *setup )
{
    return 0;
}

void xscan_init_packet( struct protoent *proto, struct xp_setup setup )
{
    switch ( proto->p_proto ) {
        case IPPROTO_ICMP:
            printf( "ICMP YO!\n" );
            break;
        case IPPROTO_TCP:
            printf( "TCP YO!\n" );
            break;
    }
    return;
}

void xhost_info( char *host, struct xp_setup *setup )
{
    struct hostent *hp;
}

short is_ip_format( char *host )
{
    int scan;
    unsigned int ip[4];
    
    scan = sscanf( host, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3] );
    if ( scan != 4 ){
        return -1;
    }
    for ( int8_t i = 0 ; i < 4 ; i++ ) {
        if ( ip[i] < 0 || ip[i] > 255 ) {
            return -1;
        }
    }
    return 0;
}

void print_icmp( struct icmp *icmp )
{
    ;
}

void __diE__( int sig )
{
    ;
}