#include "icmp.h"

short xscan_build_icmp( uint16_t type, pid_t pid, uint16_t csum, char *sbuff )
{
    uint16_t seq = 0;
    struct icmp *icmp;
    
    icmp = (struct icmp *) (sbuff + IPV4_H_SIZE);

    icmp->icmp_type  = type;
    icmp->icmp_code  = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id    = pid;
    icmp->icmp_seq   = seq++;

    if ( !csum ) {
        icmp->icmp_cksum = k_cksum( (uint16_t *) icmp, ICMP_SIZE );
    } else {
        icmp->icmp_cksum = csum;
    }

    printf( "ICMP Type -> %d\n", type );
    printf( "ICMP Pid  -> %d\n", pid );
    printf( "ICMP Checksum  -> %d\n", icmp->icmp_cksum );
    return 0;
}