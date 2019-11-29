#include "xscan_sniffer.h"

void packet_handler( u_char *args, const struct pcap_pkthdr *header, 
                     const u_char *packet )
{   
    char scan_ip[20];
    char src_ip[20];
    char dst_ip[20];
    uint16_t src_port;
    uint16_t dst_port;
    struct ip *ip = (struct ip *) (packet + 14);
    struct tcphdr *tcp;
    struct icmp *icmp;
    struct xp_stats *stats = (struct xp_stats *) args;
    
    LB2IP( stats->scan_ip, scan_ip );
    strcpy( src_ip, inet_ntoa( ip->ip_src ) );
    strcpy( dst_ip, inet_ntoa( ip->ip_dst ) );

    switch ( ip->ip_p )
    {
        case IPPROTO_TCP:
            if ( strcmp( dst_ip, setup.ip ) == 0 && strcmp( src_ip, scan_ip ) == 0 )
            {
                tcp = (struct tcphdr *) (packet + 14 + ((ip->ip_hl & 0x0f) * 4));
                src_port = ntohs( tcp->th_sport );
                dst_port = ntohs( tcp->th_dport );

                // is ack to our syn ? xDD
                if ( tcp->syn && tcp->ack ) {
                    printf( "%s -> %d:%d\n", src_ip, src_port, dst_port );
                }

                if ( tcp->rst ) {
                    printf( "%s -> %d:%d (CLOSED)\n", src_ip, src_port, dst_port );
                }
            }
            break;

        case IPPROTO_ICMP:
            if ( strcmp( dst_ip, setup.ip ) == 0 && strcmp( src_ip, scan_ip ) == 0 )
            {
                icmp = (struct icmp *) (packet + 14 + ((ip->ip_hl & 0x0f) * 4));
                printf( "%d\n", icmp->icmp_code );
            }
            break;
    }
    return;
}

void * scan_sniffer( void *st )
{
    pcap_t *handle;
    int timeout = 0;
    int promisc = 0;

    handle = pcap_open_live( setup.iface, BUFSIZ, promisc, timeout, xscan_errbuf );
    if ( !handle ) {
        __die( "%s", xscan_errbuf );
    }

    pcap_loop( handle, -1, packet_handler, (void *) st );
    pcap_close( handle );
    return NULL;
}