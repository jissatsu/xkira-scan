#ifndef __XKIRA_INCLUDE_H
#define __XKIRA_INCLUDE_H 1

#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define IPV4_H_SIZE sizeof( struct ip )
#define TCP_H_SIZE  sizeof( struct tcphdr )
#define ICMP_SIZE   sizeof( struct icmp )

#endif