#ifndef __KIRA_NET
#define __KIRA_NET 1

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

inline __attribute__((always_inline)) void CNVRT_IP( const char *ip, 
                                              uint8_t *dst )
{
    char frag[4];
    uint8_t rtv[4];
    int i, j;

    i = 0;
    j = 0;

    while ( *ip != '\0' ) {
        if ( *ip == '.' ) {
            frag[i] = '\0', i = 0, rtv[j++] = atoi( frag ), ip++;
        } else {
            frag[i++] = *ip++;
        }
    }
    frag[i] = '\0';
    rtv[j]  = atoi( frag );
    memcpy( dst, rtv, 4 );
    return;
}

inline __attribute__((always_inline)) uint32_t IP2LB( const char *ip )
{
    uint32_t rtv = 0;
    uint8_t _ip[4];
    
    CNVRT_IP( ip, _ip );
    rtv =
        (_ip[0] << 24) |
        (_ip[1] << 16) |
        (_ip[2] <<  8) |
        (_ip[3] <<  0);
    return rtv;
}

inline __attribute__((always_inline)) const char * LB2IP( uint32_t _cp )
{
    return NULL;
}

#ifdef __cplusplus
}
#endif

#endif