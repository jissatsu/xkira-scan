#include "bits.h"
#include "kira-scan.h"

short __xscan_init__( const char **argv, struct xp_setup *setup )
{
    return 0;
}

uint16_t k_cksum( uint16_t *buff, int size )
{
    uint32_t sum  = 0;
    while ( size > 1 ) {
        sum += *buff++;
        size -= 2;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~((uint16_t) sum);
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

void xhost_info( char host, struct xp_setup *setup )
{
    ;
}

void __diE__( int sig )
{
    ;
}