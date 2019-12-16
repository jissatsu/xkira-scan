#include "net.h"

uint32_t calc_nhosts( short subnet )
{
    char mask[30];
    uint32_t int_msk;
    uint32_t nhosts;

    if( MSK_FR_SUB( subnet, mask ) < 0 ){
        return -1;
    }
    
    int_msk = IP2LB( mask );
    nhosts  = int_msk ^ 0xFFFFFFFF;
    return nhosts;
}

/* calculate the start ip address based on the `ip` and `subnet` */
uint32_t net_off( char *ip, short subnet )
{
    char mask[30];
    uint32_t int_ip, int_msk;
    uint32_t off = 0;

    if( MSK_FR_SUB( subnet, mask ) < 0 ){
        return -1;
    }

    int_ip  = IP2LB( ip );
    int_msk = IP2LB( mask );
    off     = int_ip & int_msk;
    return off;
}

char * portservice( uint16_t port )
{
    char *service;
    struct servent *serv;

    service = (char *) malloc( 40 );
    if ( !service ) {
        return NULL;
    }
    serv = getservbyport( htons( port ), NULL );
    if ( !serv ) {
        strcpy( service, "Unknown" );
    }
    if ( serv ) {
        strcpy( service, serv->s_name );
    }
    return service;
}

/*
 * Get the ip address of a network interface
 * @param `char *iface` This is where the device's name is stored
 * @param `char *dst` This is where the device's ip address is stored
 * @return 0 (success) or -1 (error)
*/
short net_ip( char *iface, char *dst )
{
    int num;
    short flags;
    struct ifreq *req;
    struct sockaddr_in *addr;

    req = IF_LIST( &num );
    if ( !req ) {
        return -1;
    }
    
    if ( num <= 0 ) {
        sprintf(
            xscan_errbuf, "%s", "No devices found!"
        );
        return -1;
    }

    for ( int i = 0 ; i < num ; i++ )
    {
        flags = IF_FLAGS( req->ifr_name );
        if ( flags == -1 ) {
            return -1;
        }
        // get the first active device that is not a loopback
        if ( flags & IFF_RUNNING && !(flags & IFF_LOOPBACK) )
        {
            strcpy( iface, req->ifr_name );
            addr = (struct sockaddr_in *) &req->ifr_addr;
            strcpy( dst, inet_ntoa( addr->sin_addr ) );
            return 0;
        }
        req++;
    }
    return -1;
}

/* Retreive a list of available interfaces */
struct ifreq * IF_LIST( int *num )
{
    int sockfd;
    struct ifconf iconf;
    static struct ifreq req[64];

    if ( (sockfd = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
        sprintf(
            xscan_errbuf, "%s", strerror( errno )
        );
        return NULL;
    }

    iconf.ifc_len = sizeof( req );
    iconf.ifc_req = req;
    if ( ioctl( sockfd, SIOCGIFCONF, &iconf ) < 0 ) {
        sprintf(
            xscan_errbuf, "%s", strerror( errno )
        );
        close( sockfd );
        return NULL;
    }
    
    for ( int i = 1 ; strlen( req[i - 1].ifr_name ) > 0 ; i++ ) {
        *num = i;
    }
    close( sockfd );
    return req;
}

// Get the active flag word of the device
short IF_FLAGS( char *iface )
{
    int sockfd;
    struct ifreq req;
    
    if ( (sockfd = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
        sprintf(
            xscan_errbuf, "%s", strerror( errno )
        );
        return -1;
    }

    strcpy( req.ifr_name, iface );
    if ( ioctl( sockfd, SIOCGIFFLAGS, &req ) < 0 ) {
        sprintf(
            xscan_errbuf, "%s", strerror( errno )
        );
        return -1;
    }
    return req.ifr_flags;
}

/* 
 * check if the given string is an ip
 * @param `const char *str` The string to check
 */
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