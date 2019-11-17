#include "net.h"

// notify the kernel about our ipv4 header
void sockopt_hdrincl( int *sock, int *hdrincl )
{
    int opt = 1;
    int st = setsockopt(
        *sock,
        IPPROTO_IP,
        IP_HDRINCL,
        &opt,
        sizeof( opt )
    );
    *hdrincl = (st == 0) ? 1 : 0 ;
}

short net_ip( char *dst )
{
    return 0;
}

char * is_ip( const char *str )
{
    int scan;
    static char ip[30];
    unsigned int b_ip[4];
    
    scan = sscanf( 
        str, "%d.%d.%d.%d", &b_ip[0], &b_ip[1], &b_ip[2], &b_ip[3]
    );
    if ( scan == EOF ) {
        return NULL;
    }
    
    for ( short i = 0 ; i < 4 ; i++ ) {
        if ( b_ip[i] < 0 || b_ip[i] > 255 ) {
            return NULL;
        }
    }
    sprintf(
        ip, "%d.%d.%d.%d", b_ip[0], b_ip[1], b_ip[2], b_ip[3]
    );
    return ip;
}