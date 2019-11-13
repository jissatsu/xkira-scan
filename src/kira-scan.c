#include "output.h"
#include "inline.h"
#include "kira-scan.h"

short __xscan_init__( const char **argv, struct xp_setup *setup )
{
    uint16_t *ports;
    return 0;
}

void xscan_init_packet( struct protoent *proto )
{
    switch ( proto->p_proto ) {
        case IPPROTO_ICMP:
            printf( "ICMP YO!\n" );
            break;
        case IPPROTO_TCP:
            printf( "TCP YO!\n" );
            break;
    }
}

/* Get hostname and ip address of a host */
short xhost_info( char *host, struct xp_setup *setup )
{
    short frmt;
    struct hostent *hp;
    
    if ( !host )
        xset_buff( xscan_errbuf, "%s", strerror( errno ) );
        return -1;
    
    frmt = xscan_hstr_format( host );
    switch ( frmt ) {
        case X_IP:
            // hp = gethostbyaddr();
            break;
        case X_NM:
            hp = gethostbyname( host );
            break;
    }

    setup->_host.name = hp->h_name;
    setup->_host.ip   = hp->h_name;
    return 0;
}

/* Parse the string that specifies the port range */
uint16_t * x_ports( char *ports )
{
    return NULL;
}

short xscan_hstr_format( char *host )
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

void print_icmp( void )
{
    ;
}

void __diE__( int sig )
{
    ;
}