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
            }
        }

        if ( proto == IPPROTO_ICMP && ip->ip_p == proto )
        {
            icmp = (struct icmp *) (packet + 14 + ((ip->ip_hl & 0x0f) * 4));
            printf( "%d\n", icmp->icmp_code );
        }
    }
    return;
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
    if ( nports == 1 )
    {
        ports[0].port  = port;
        ports[0].state = state;
    }

    if ( nports > 1 )
    {
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
    //static int i = 0;
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

            if ( item == search ) {
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
            if ( strcmp( ip, stats->hosts[i].ip ) == 0 ) {
                return 0;
            }
        }
    }
    return -1;
}