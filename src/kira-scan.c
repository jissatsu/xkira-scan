#include "kira-scan.h"

/* Initialize the packet based on the protocol */
struct xp_packet * xscan_init_packet( int proto, char *src_ip, char *dst_ip, uint16_t sport, uint16_t dport, char *sbuff )
{
    pid_t pid;
    static struct xp_packet pkt;

    pid = setup.pid;
    switch ( proto ) {
        case IPPROTO_ICMP:
            if( (pkt.icmp = xscan_build_icmp( ICMP_ECHO, pid, sbuff )) == NULL ){
                return NULL;
            }
            printf( "Dst host -> %s\n", dst_ip );
            printf( "Src port -> %d\n", sport );
            printf( "Dst port -> %d\n\n", dport );
            break;
        case IPPROTO_TCP:
            /* tcp_flags.syn = 1;
            if ( (pkt.tcp = xscan_build_tcp( tcp_flags, sport, dport, sbuff )) == NULL ) {
                return NULL;
            } */
            printf( "Dst host -> %s\n", dst_ip );
            printf( "Src port -> %d\n", sport );
            printf( "Dst port -> %d\n\n", dport );
            break;
    }
    if ( (pkt.ip = xscan_build_ipv4( proto, pid, src_ip, dst_ip, sbuff)) == NULL ) {
        return NULL;
    }
    return &pkt;
}

/* initialize the stats */
void __init_stats__( struct xp_stats *stats )
{
    if ( setup._host.subnet ) {
        stats->scan_ip = net_off( setup._host.ip, setup._host.subnet ); /* start ip address e.g 192.168.0.1 */
        stats->nhosts  = calc_nhosts( setup._host.subnet );
        stats->scan_ip++;
    } else {
        stats->nhosts  = 1;
        stats->scan_ip = IP2LB( setup._host.ip );
    }

    // calculate number of ports to scan
    if ( setup._ports.range ) {
        stats->nports = setup._ports.end - setup._ports.start;
    } else {
        stats->nports = 1;
    }
    
    // total number of packets
    stats->tpkts = stats->nhosts * stats->nports;
    return ;
}

/* send the packet */
short xscan_send_packet( int *sock, const void *buff, size_t size )
{
    int nbytes;
    struct sockaddr_in dst_addr;
    
    memset( &dst_addr, '\0', sizeof( dst_addr ) );
    // the port and ip address here dont matter because we are setting them in the tcp and ipv4 headers
    dst_addr = net_sockaddr( AF_INET, 0, NULL );
    nbytes   = sendto(
        *sock, buff, size, 0, (struct sockaddr *) &dst_addr, sizeof( dst_addr )
    );
    return (nbytes < 0) ? -1 : 0 ;
}


short xscan_scan_host( int *sock, short type, struct xp_stats *stats, char *src_ip, char *dst_ip )
{
    short proto;
    short dd;
    char sbuff[400];
    uint16_t src_port, dst_port;
    struct xp_packet *pkt;
    
    memset( sbuff, '\0', sizeof( sbuff ) );
    switch ( setup.type )
    {
        case X_SYN:
        	src_port = rand() % 8000;
            dst_port = setup._ports.start;
        	proto    = IPPROTO_TCP;
			break;

		case X_ICMP:
        	src_port = 0;
            dst_port = 0;
        	proto    = IPPROTO_ICMP;
			break;
	}
    dd = (stats->nports > 1) ? 1 : 0 ;

    for ( uint32_t i = 0 ; i < stats->nports + dd ; i++ )
    {
        if ( (pkt = xscan_init_packet( proto, src_ip, dst_ip, src_port, dst_port, sbuff )) == NULL ) {
            sprintf(
                xscan_errbuf,
                "%s", "Packet initialization error!\n"
            );
            return -1;
        }
        
        if ( xscan_send_packet( sock, (const void *) sbuff, sizeof( sbuff ) ) < 0 ) {
            sprintf(
                xscan_errbuf,
                "%s", "Error sending packet!\n"
            );
            return -1;
        }

        if ( stats->nports > 1 ) {
            dst_port++;
        }
        mssleep( 0.3 );
    }
    return 0;
}

void __xscan_initiate__( struct xp_stats *stats )
{
    int sock;
    int hdrincl;
    char dst_ip[30];

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

    __init_stats__( stats );
    #ifdef DEBUG
        v_out( VDEBUG, "%s: Total hosts   -> %d\n", __FILE__, stats->nhosts );
        v_out( VDEBUG, "%s: Total ports   -> %d\n", __FILE__, stats->nports );
        v_out( VDEBUG, "%s: Total packets -> %d\n", __FILE__, stats->tpkts );
    #endif

<<<<<<< HEAD
=======
    switch ( setup.type ) {
        case X_SYN:
        	src_port = rand() % 8000;
            	dst_port = setup._ports.start;
        	proto    = IPPROTO_TCP;
		break;

	case X_ICMP:
        	src_port = 0;
            	dst_port = 0;
        	proto    = IPPROTO_ICMP;
		break;
    }

    if ( stats->nports > 1 ) {
        dd = 1;
    } else {
        dd = 0;
    }

>>>>>>> dc827626c3ae5ccabc8fdf7990dc161301190d61
    for ( uint32_t i = 0 ; i < stats->nhosts ; i++ )
    {
        LB2IP( stats->scan_ip, dst_ip );
        if ( xscan_scan_host( &sock, setup.type, stats, setup.ip, dst_ip ) < 0 ) {
            __die( "%s", xscan_errbuf );
        }
        stats->nsent++;
        stats->scan_ip++;
    }
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
