#include "kira-scan.h"

void __xscan_initiate__( struct xp_stats *stats )
{
    int sock;
    int hdrincl;

    if ( (sock = socket( AF_INET, SOCK_RAW, IPPROTO_RAW )) < 0 ) {
        __die( "%s", strerror( errno ) );
    }

    sockopt_hdrincl( &sock, &hdrincl );
    #ifdef DEBUG
        if ( hdrincl )
            v_out( VDEBUG, "%s: %s", __FILE__, "IP_HDRINCL success!\n" );
        else
            v_out( VDEBUG, "%s: %s", __FILE__, "IP_HDRINCL failure!\n" );
    #endif

    if ( setup.type == X_ICMP ) {
        if ( xscan_icmp( &sock, &setup._host, stats ) < 0 ) {
            __die( "%s", xscan_errbuf );
        }
    }

    if( setup.type == X_SYN ) {
        if ( xscan_syn( &sock, &setup._host, &setup._ports, stats ) < 0 ) {
            __die( "%s", xscan_errbuf );
        }
    }
    return;
}

/* perform icmp scan */
short xscan_icmp( int *sock, struct host *host, struct xp_stats *stats )
{
    char sbuff[400];
    char dst_ip[30];
    struct xp_packet *pkt;

    memset( sbuff, '\0', sizeof( sbuff ) );

    if ( host->subnet ) {
        stats->scan_ip = net_off( host->ip, host->subnet ); /* start ip address e.g 192.168.0.1 */
        stats->nhosts  = calc_nhosts( host->subnet );
        stats->scan_ip++;
    } else {
        stats->nhosts  = 1;
        stats->scan_ip = IP2LB( host->ip );
    }
    stats->tpkts = stats->nhosts;
    #ifdef DEBUG
        v_out( VDEBUG, "%s - xscan_icmp(): Total hosts   -> %d\n", __FILE__, stats->nhosts );
        v_out( VDEBUG, "%s - xscan_icmp(): Total packets -> %d\n", __FILE__, stats->tpkts );
    #endif

    for ( uint32_t i = 0 ; i < stats->tpkts ; i++ )
    {
        LB2IP( stats->scan_ip, dst_ip );
        if ( (pkt = xscan_init_packet( IPPROTO_ICMP, setup.ip, dst_ip, NULL, sbuff )) == NULL ) {
            sprintf(
                xscan_errbuf,
                "Packet initialization error!\n"
            );
            return -1;
        }
        if ( xscan_send_packet( sock, (const void *) sbuff, sizeof( sbuff ) ) < 0 ) {
            sprintf(
                xscan_errbuf,
                "Error sending packet!\n"
            );
            return -1;
        }
        stats->nsent++;
        printf( "%d\n", stats->nsent );
        stats->scan_ip += ( stats->nhosts > 1 ) ? 1 : 0 ;
        mssleep( 0.3 );
    }
    return 0;
}

/* perform syn scan */
short xscan_syn( int *sock, struct host *host, struct ports *ports, struct xp_stats *stats )
{
    char sbuff[400];
    char dst_ip[30];
    struct xp_packet *pkt;

    memset( sbuff, '\0', sizeof( sbuff ) );

    if ( host->subnet ) {
        stats->scan_ip = net_off( host->ip, host->subnet ); /* start ip address e.g 192.168.0.1 */
        stats->nhosts  = calc_nhosts( host->subnet );
        stats->scan_ip++;
    } else {
        stats->nhosts  = 1;
        stats->scan_ip = IP2LB( host->ip );
    }

    if ( (pkt = xscan_init_packet( IPPROTO_TCP, setup.ip, dst_ip, &setup._ports, sbuff )) == NULL ) {
        __die( "%s", "Packet initialization error!\n" );
    }
    if ( xscan_send_packet( sock, (const void *) sbuff, sizeof( sbuff ) ) == 0 ) {
        stats->nsent++;
    }
    return 0;
}

/* Initialize the packet based on the protocol */
struct xp_packet * xscan_init_packet( int proto, char *src_ip, char *dst_ip, struct ports *ports, char *sbuff )
{
    pid_t pid;
    static struct xp_packet pkt;

    pid = setup.pid;
    if ( proto == IPPROTO_ICMP ){
        if( (pkt.icmp = xscan_build_icmp( ICMP_ECHO, pid, sbuff )) == NULL ){
            return NULL;
        }
    }
    
    if ( proto == IPPROTO_TCP ){
        //if (  ) {

        //}
    }
    
    if ( (pkt.ip = xscan_build_ipv4( proto, pid, src_ip, dst_ip, sbuff)) == NULL ) {
        return NULL;
    }
    return &pkt;
}

/* send the packet */
short xscan_send_packet( int *sock, const void *buff, size_t size )
{
    int nbytes;
    struct sockaddr_in dst_addr;
    
    memset( &dst_addr, '\0', sizeof( dst_addr ) );
    // using random socket address here since we are building the ipv4 header
    dst_addr = net_sockaddr( AF_INET, 0, NULL );
    nbytes   = sendto(
        *sock, buff, size, 0, (struct sockaddr *) &dst_addr, sizeof( dst_addr )
    );
    return (nbytes < 0) ? -1 : 0 ;
}

// start the scan sniffer thread
short xscan_start_sniffer( struct xp_stats *stats )
{
    int err;
    pthread_t thread;
    
    err = pthread_create(
        &thread,
        NULL,
        scan_sniffer,
        (void *) stats
    );

    if ( err ) {
        sprintf(
            xscan_errbuf,
            "Error spawning scan_sniffer thread!\n"
        );
        return -1;
    }
    return 0;
}

void __End__( int sig )
{
    return;
}