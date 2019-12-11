#include "xscan_sniffer.h"

void packet_handler( u_char *args, const struct pcap_pkthdr *header, 
                     const u_char *packet )
{   
    char scan_ip[20];
    char src_ip[20];
    char dst_ip[20];
    short proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t dec_ip;
    struct ip *ip = (struct ip *) (packet + 14);
    struct tcphdr *tcp;
    struct icmp *icmp;
    struct xp_stats *stats = (struct xp_stats *) args;
    
    //LB2IP( stats->scan_ip, scan_ip );
    strcpy( src_ip, inet_ntoa( ip->ip_src ) );
    strcpy( dst_ip, inet_ntoa( ip->ip_dst ) );

    if ( setup.type == X_SYN ) {
        proto = IPPROTO_TCP;
    }
    
    if ( setup.type == X_ICMP ) {
        proto = IPPROTO_ICMP;
    }

    // source ip in decimal format
    dec_ip = IP2LB( src_ip );

    // the packet must be for us and the source ip must be any of the ips we are scanning
    if ( strcmp( dst_ip, setup.ip ) == 0 && is_scan_host( src_ip, stats ) == 0 )
    {
        if ( proto == IPPROTO_TCP && ip->ip_p == proto )
        {
            tcp      = (struct tcphdr *) (packet + 14 + ((ip->ip_hl & 0x0f) * 4));
            src_port = ntohs( tcp->th_sport );
            dst_port = ntohs( tcp->th_dport );
            
            if ( is_scan_port( src_port ) == 0 )
            {
                if ( tcp->syn && tcp->ack ) {
                    #ifdef DEBUG
                        v_out( VDEBUG, "%s:%d -> %s:%d - [ACK]\n", src_ip, src_port, dst_ip, dst_port );
                    #endif
                    xscan_add_port(
                        src_port,
                        XOPEN,
                        stats->scanned_ports,
                        stats->nports
                    );
                }
                else if ( tcp->rst ) {
                    #ifdef DEBUG
                        v_out( VDEBUG, "%s:%d -> %s:%d - [RST]\n", src_ip, src_port, dst_ip, dst_port );
                    #endif
                    xscan_add_port(
                        src_port,
                        XCLOSED,
                        stats->scanned_ports,
                        stats->nports
                    );
                }
                xscan_set_portresp( src_ip, stats->hosts, stats->nhosts );
            }
        }

        if ( proto == IPPROTO_ICMP && ip->ip_p == proto )
        {
            icmp = (struct icmp *) (packet + 14 + ((ip->ip_hl & 0x0f) * 4));
            // packet id must match our pid
            if ( ntohs( icmp->icmp_id ) != setup.pid ) {
                return;
            }
            if ( icmp->icmp_type == ICMP_ECHOREPLY ) {
                printf( "icmp->icmp_id = %d and host [%s] is UP\n", icmp->icmp_id, src_ip );
            }
        }
    }
    // xscan_accum_stats( stats );
    return;
}

short xscan_start_receiver( struct xp_stats *stats )
{
    int err;
    err = pthread_create( &thread, NULL, scan_sniffer, (void *) stats );
    if ( err ) {
        sprintf(
            xscan_errbuf,
            "Error spawning scan_sniffer thread!\n"
        );
        return -1;
    }
    #ifdef DEBUG
        v_out( VDEBUG, "%s: %s", __FILE__, "Spawned scan sniffer!\n" );
    #endif
    return 0;
}

void * scan_sniffer( void *st )
{
    pcap_t *handle;
    int timeout = 0;
    int promisc = 0;

    handle = pcap_open_live(
        setup.iface,
        BUFSIZ,
        promisc,
        timeout,
        xscan_errbuf
    );
    
    if ( !handle ) {
        __die( "%s", xscan_errbuf );
    }

    pcap_loop( handle, -1, packet_handler, (void *) st );
    pcap_close( handle );
    return NULL;
}

void xscan_set_portresp( char *ip, SCHosts *hosts, uint16_t nhosts )
{
    uint32_t id    = IP2LB( ip );
    uint32_t right = hosts[nhosts - 1].id;
    uint32_t left  = hosts[0].id;
    uint16_t index = (right - left) - (right - id);
    
    if ( !hosts[index].port_resp ) {
        hosts[index].port_resp = 1;
    }
    return;
}

void xscan_add_port( uint16_t port, port_t state, SCPorts *ports, uint16_t nports )
{
    uint16_t index;

    switch ( state ) {
        case XCLOSED:
            stats.nclosed++;
            break;
        case XOPEN:
            stats.nopen++;
            break;
    }

    if ( nports == 1 ) {
        ports[0].port  = port;
        ports[0].state = state;
    }

    if ( nports > 1 ) {
        index = port - setup._ports.start;
        ports[index].port  = port;
        ports[index].state = state;
    }
}

short is_scan_port( uint16_t port )
{   
    if ( setup._ports.range ) {
        if ( port >= setup._ports.start && port <= setup._ports.end ) {
            return 0;
        }
    } else {
        if ( port == setup._ports.start ) {
            return 0;
        }
    } return -1;
}

short is_scan_host( char *ip, struct xp_stats *stats )
{
    if ( stats->nhosts > 255 )
    {
        uint16_t size   = stats->nhosts;
        uint16_t m      = 0;
        uint16_t left   = 0;
        uint16_t right  = size - 1;
        uint32_t search = IP2LB( ip );
        uint32_t item   = 0;

        while ( left <= right )
        {
            m = (left + right) / 2;
            if ( m < 0 || m > size ) {
                return -1;
            }
            item = stats->hosts[m].id;

            // we found the host and is currently in scan
            if ( item == search && stats->hosts[m].in_scan ) {
                // change host's state to up
                if ( !stats->hosts[m].state ) {
                    stats->hosts[m].state = 1;
                }
                // printf( "aaaa -> %d - %d\n", stats->hosts[m].in_scan, stats->hosts[m].state );
                return 0;
            }

            if ( item < search ) {
                left = m + 1;
            }
            else if ( item > search ) {
                right = m - 1;
            }
        }
        //printf( "%s - %u - %u\n", ip, IP2LB( ip ), stats->hosts[i++].id );
        return -1;
    }
    
    if ( stats->nhosts <= 255 )
    {
        for ( register uint16_t i = 0 ; i < stats->nhosts ; i++ ) {
            if ( strcmp( ip, stats->hosts[i].ip ) == 0 && stats->hosts[i].in_scan ) {
                if ( !stats->hosts[i].state ) {
                    stats->hosts[i].state = 1;
                }
                // printf( "zzzz -> %d - %d\n", stats->hosts[i].in_scan, stats->hosts[i].state );
                return 0;
            }
        }
    }
    return -1;
}
