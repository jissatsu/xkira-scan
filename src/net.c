#include "net.h"

/*
 * Notify the kernel about our ipv4 header
 * @param `int *sock` A pointer to a socket descriptor
 * @param `int *hdrincl`
*/
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

/* Generate a random ip address */
char * rand_addr( void )
{
    uint8_t addr[4];
    time_t t;
    static char rand_addr[30];

    srand( (unsigned) time( &t ) );
    addr[0] = rand() % 255;
    addr[1] = rand() % 255;
    addr[2] = rand() % 255;
    addr[3] = rand() % 255;

    sprintf( rand_addr, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3] );
    return rand_addr;
}

uint32_t calc_nhosts( char *ip, short subnet )
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

/* Create an address structure of type `struct sockaddr_in` */
struct sockaddr_in net_sockaddr( uint16_t family, uint16_t port, char *addr )
{
    struct sockaddr_in sock_addr;

    if ( port < 1 || port > 65535 ) {
        port = 80;
    }
    sock_addr.sin_family      = family;
    sock_addr.sin_port        = htons( port );
    sock_addr.sin_addr.s_addr = inet_addr( ( !addr ) ? rand_addr() : addr  );
    return sock_addr;
}

/*
 * Get the ip address of a network interface
 * @param `const char *iface` The network interface's name
 * @param `char *dst` On success it gets assigned the ip address
 * @return 0 (success) or -1 (error)
*/
short net_ip( const char *iface, char *dst )
{
    int sockfd;
    struct ifreq req;
    struct sockaddr_in *addr;

    if ( (sockfd = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
        sprintf( 
            xscan_errbuf, "%s", strerror( errno )
        );
        return -1;
    }

    strcpy( req.ifr_name, iface );
    if ( ioctl( sockfd, SIOCGIFADDR, &req ) < 0 ) {
        sprintf(
            xscan_errbuf, "%s", strerror( errno )
        );
        return -1;
    }

    addr = (struct sockaddr_in *) &req.ifr_addr;
    strcpy( dst, inet_ntoa( addr->sin_addr ) );
    return 0;
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