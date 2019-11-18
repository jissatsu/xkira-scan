#include "ipv4.h"

short xscan_build_ipv4( int proto, const char *src_ip, const char *dst_ip, uint16_t cksum, char *sbuff )
{
    struct in_addr *src, *dst;
    printf( "Protocol -> %d\n", proto );
    printf( "Src ip   -> %s\n", src_ip );
    printf( "Dst ip   -> %s\n", dst_ip );
    return 0;
}