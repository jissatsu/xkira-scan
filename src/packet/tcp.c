#include "tcp.h"

struct tcphdr * xscan_build_tcp( struct tcp_flags flags, char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, char *data, char *sbuff )
{
    char *pseudobuff;
    char databuff[10];
    static struct tcphdr *tcp;
    struct pseudo_hdr *pshdr;

    tcp = (struct tcphdr *) &sbuff[IPV4_H_SIZE];
    tcp->source  = htons( src_port );
    tcp->dest    = htons( dst_port );
    tcp->seq     = 0;
    tcp->ack_seq = 0;
    tcp->doff    = 5;
    tcp->fin     = flags.fin;
	tcp->syn     = flags.syn;
	tcp->rst     = flags.rst;
	tcp->psh     = flags.psh;
	tcp->ack     = flags.ack;
	tcp->urg     = flags.urg;
    tcp->window  = htons( 155 );
    tcp->check   = htons( 0x3fc1 );
    tcp->urg_ptr = 0;

    if ( !data ) {
        strcpy( databuff, "lol xD" );
    } else {
        strcpy( databuff, data );
    }
    strcpy( &sbuff[IPV4_H_SIZE + TCP_H_SIZE], databuff );
    return tcp;
}