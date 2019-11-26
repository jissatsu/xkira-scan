#include "tcp.h"

struct tcphdr * xscan_build_tcp( struct tcp_flags flags, char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, char *data, char *sbuff )
{
    char *pseudobuff;
    char databuff[10];
    static struct tcphdr *tcp;
    struct pseudo_hdr pshdr;

    tcp = (struct tcphdr *) &sbuff[IPV4_H_SIZE];
    tcp->source = htons (1234);
	tcp->dest = htons (80);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->doff = 5;	//tcp header size
	tcp->fin=0;
	tcp->syn=1;
	tcp->rst=0;
	tcp->psh=0;
	tcp->ack=0;
	tcp->urg=0;
	tcp->window = htons (5840);	/* maximum allowed window size */
	tcp->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcp->urg_ptr = 0;

    if ( !data ) {
        strcpy( databuff, "lol xD" );
    } else {
        strcpy( databuff, data );
    }
    strcpy( &sbuff[IPV4_H_SIZE + TCP_H_SIZE], databuff );
    return tcp;
}