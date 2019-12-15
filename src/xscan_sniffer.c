#include "xscan_sniffer.h"

void packet_handler( u_char *args, const struct pcap_pkthdr *header, 
                     const u_char *packet )
{   
    char src_ip[20];
    char dst_ip[20];
    short proto;
    uint16_t src_port;
    uint16_t dst_port;
    struct ip *ip = (struct ip *) (packet + 14);
    struct tcphdr *tcp;
    struct icmp *icmp;
    struct xp_stats *stats = (struct xp_stats *) args;
    
    strcpy( src_ip, inet_ntoa( ip->ip_src ) );
    strcpy( dst_ip, inet_ntoa( ip->ip_dst ) );

    if ( setup.type == X_SYN ) {
        proto = IPPROTO_TCP;
    }
    
    if ( setup.type == X_ICMP ) {
        proto = IPPROTO_ICMP;
    }

    // the packet must be for us and the source ip must be same as the current host's ip
    if ( strcmp( dst_ip, setup.ip ) == 0 && strcmp( src_ip, stats->current_host.ip ) == 0 )
    {
        // mark current host as `up`
        if ( !stats->current_host.state ) {
            stats->current_host.state = 1;
        }

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
                        stats->current_host.ports,
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
                        stats->current_host.ports,
                        stats->nports
                    );
                }
                // host responded on a port
                if ( !stats->current_host.port_resp ) {
                    stats->current_host.port_resp = 1;
                }
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

void xscan_add_port( uint16_t port, port_t state, SCPorts *ports, uint16_t nports )
{
    uint16_t index;

    switch ( state ) {
        case XCLOSED:
            stats.current_host.nclosed++;
            break;
        case XOPEN:
            stats.current_host.nopen++;
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