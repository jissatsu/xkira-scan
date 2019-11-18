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