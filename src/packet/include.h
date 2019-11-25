#ifndef __XKIRA_INCLUDE_H
#define __XKIRA_INCLUDE_H 1

#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

struct pseudo_hdr
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

#define IPV4_H_SIZE sizeof( struct ip )
#define TCP_H_SIZE  sizeof( struct tcphdr )
#define ICMP_SIZE   sizeof( struct icmp )
#define PSEUDO_SIZE sizeof( struct pseudo_hdr )

#endif