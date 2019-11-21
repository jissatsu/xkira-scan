#include "kira-scan.h"

void __xscan_initiate__( struct xp_stats *stats,
                         void (*shandler)(struct xp_stats *stats) )
{
    int sock;
    int hdrincl;
    int nbytes;
    int proto;
    char sbuff[400];
    char *dst_ip;
    struct xp_packet *pkt;
    struct sockaddr_in dst_addr;

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

    memset( sbuff, '\0', sizeof( sbuff ) );
    switch ( setup.type ) {
        case X_ICMP:
            proto = IPPROTO_ICMP;
            break;
        case X_SYN:
            proto = IPPROTO_TCP;
            break;
    }

    if ( !setup._host.subnet ) {
        dst_ip = setup._host.ip;
    } else {
        stats->start  = net_off( setup._host.ip, setup._host.subnet );
        stats->nhosts = calc_nhosts( setup._host.ip, setup._host.subnet );
    }

    stats->tpkts = 0;// number of hosts (number of ip addresses to scan) + number of ports

    for ( uint32_t i = 0 ; i < stats->tpkts ; i++ ) {
        if ( (pkt = xscan_init_packet( proto, setup.ip, dst_ip, &setup._ports, sbuff )) == NULL ) {
            __die( "%s", "Packet initialization error!\n" );
        }
        //if ( xscan_send_packet( sbuff ) ) {
        //    stats->nsent++;
        //}
    }
    return;
}

/* Initialize the packet base on the protocol */
struct xp_packet * xscan_init_packet( int proto, char *src_ip, char *dst_ip, struct ports *ports, char *sbuff )
{
    pid_t pid;
    static struct xp_packet pkt;

    pid = setup.pid;
    if ( proto == IPPROTO_ICMP ){
        if( (pkt.icmp = xscan_build_icmp( ICMP_ECHO, pid, -1, sbuff )) == NULL ){
            return NULL;
        }
    }
    
    if ( proto == IPPROTO_TCP ){
        //if (  ) {

        //}
    }
    
    if ( (pkt.ip = xscan_build_ipv4( proto, pid, src_ip, dst_ip, -1, sbuff)) == NULL ) {
        return NULL;
    }
    printf( "%s - %s\n", src_ip, dst_ip );
    return &pkt;
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