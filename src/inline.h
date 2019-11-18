#ifndef __KIRA_NET
#define __KIRA_NET 1

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef __GNUC__
    #define __inline __attribute__((always_inline))
#else
    #define __inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Generic checksum */
inline __inline uint16_t k_cksum( uint16_t *buff, int size )
{
    uint32_t sum  = 0;
    while ( size > 1 )
    {
        sum += *buff++;
        size -= 2;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~((uint16_t) sum);
}

/* Convert an ip address from string to a 4 byte array */
inline __inline void IP2B( const char *ip, uint8_t *dst )
{
    char frag[4];
    uint8_t rtv[4];
    
    if ( ip ) {
        for ( int i = 0, j = 0, k = 0 ; i < 4 ; i++ ) {
            frag[j]     = (isdigit( *ip )) ? *ip++ : '\0' ;
            frag[j + 1] = (isdigit( *ip )) ? *ip++ : '\0' ;
            frag[j + 2] = (isdigit( *ip )) ? *ip++ : '\0' ;
            frag[j + 3] = '\0';
            ip++;
            rtv[k++] = atoi( frag );
        }
        memcpy( dst, rtv, 4 );
    }
    return;
}

/* Convert an ip address from 4-byte array to string  */
inline __inline void B2IP( const uint8_t *src, char *dst )
{
    sprintf( dst, "%d.%d.%d.%d", src[0], src[1], src[2], src[3] );
    return;
}

/* Convert an ip from string to a 32-bit integer */
inline __inline uint32_t IP2LB( const char *ip )
{
    uint32_t rtv = 0;
    uint8_t _ip[4];
    
    IP2B( ip, _ip );
    rtv =
        (_ip[0] << 24) |
        (_ip[1] << 16) |
        (_ip[2] <<  8) |
        (_ip[3] <<  0);
    return rtv;
}

/* Convert a 32-bit integer to an ip string */
inline __inline void LB2IP( uint32_t _cp, char *dst )
{
    uint8_t arr[4];
    arr[0] = (_cp >> 24) & 0xff;
    arr[1] = (_cp >> 16) & 0xff;
    arr[2] = (_cp >>  8) & 0xff;
    arr[3] = (_cp >>  0) & 0xff;
    B2IP( arr, dst );
    return;
}

/*
Retrieve netmask from subnet
/16 -> 255.255.0.0
/24 -> 255.255.255.0 etc... */
inline __inline short MSK_FR_SUB( short subnet, char *mask )
{
    if ( subnet < 16 || subnet > 30 ) {
        return -1;
    }

    short max    = 32; /* netmask max size is 32 bits */
    uint32_t msk = (0xffffffff >> (max - subnet)) << (max - subnet);
    LB2IP( msk, mask );
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif