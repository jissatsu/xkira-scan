#include "icmp.h"

struct icmp * xscan_build_icmp( uint16_t type, pid_t pid, uint16_t csum, char *sbuff )
{
    static uint16_t seq = 0;
    static struct icmp *icmp;

    icmp = (struct icmp *) &sbuff[IPV4_H_SIZE];

    icmp->icmp_type  = type;
    icmp->icmp_code  = 0;
    icmp->icmp_id    = 321;
    icmp->icmp_seq   = 0;
    icmp->icmp_cksum = 0;

    if ( !csum ) {
        icmp->icmp_cksum = k_cksum( (uint16_t *) &sbuff[IPV4_H_SIZE], ICMP_SIZE );
    } else {
        icmp->icmp_cksum = csum;
    }
    return icmp;
}
