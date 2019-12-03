#include "kira-scan.h"

void __xscan_initiate__( struct xp_stats *stats )
{
    if ( __init_stats__( stats ) < 0 ) {
        __die( "%s", xscan_errbuf );
    }

    // `setup.on` means we are not performing a single scan
    // we are either scanning a subnet or a single host on a port range
    if ( setup.on ) {
        signal( SIGINT,  __End__ ); /* Ctrl + C */
        signal( SIGTERM, __End__ );
        signal( SIGQUIT, __End__ ); /* Ctrl + \ */
        signal( SIGTSTP, __End__ ); /* Ctrl + Z */
        #ifdef DEBUG
            v_out( VDEBUG, "%s: %s", __FILE__, "Registered signal handler!\n" );
        #endif
    }

    #ifdef DEBUG
        v_out( VDEBUG, "%s: Total hosts   -> %d\n", __FILE__, stats->nhosts );
        v_out( VDEBUG, "%s: Total ports   -> %d\n", __FILE__, stats->nports );
        v_out( VDEBUG, "%s: Total packets -> %d\n", __FILE__, stats->tpkts );
    #endif
    
    for ( uint32_t i = 0 ; i < stats->nhosts ; i++ )
    {
        stats->time = 0.0;
        memset( stats->scanned_ports, 0, (stats->nports + 1) * sizeof( SCPorts ) );
        
        if ( xscan_scan_host( stats, setup.ip, stats->hosts[i].ip ) < 0 ) {
            // free all stats' allocated memory
            xscan_free_stats( stats );
            __die( "%s", xscan_errbuf );
        }

        stats->current_host = stats->hosts[i].ip;
        if ( setup.verbose ) {
            xscan_print_stats( stats );
        }
    }
}

/* Initialize the packet based on the protocol */
short xscan_init_packet( int proto, char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, char *sbuff )
{
    uint32_t irand;
    libnet_ptag_t tcp, icmp, ipv4;
    
    tcp = icmp = ipv4 = LIBNET_PTAG_INITIALIZER;

    libnet_seed_prand( ltag );
    if ( (irand = libnet_get_prand( LIBNET_PR8 )) < 0 ) {
        irand = setup.pid;
    }
    // syn scan
    if ( proto == IPPROTO_TCP )
    {
        tcp = libnet_build_tcp(
            src_port,     /* source port */
            dst_port,     /* dest port */
            irand,        /* sequence number */
            0x0000,       /* acknowledgement */
            TH_SYN,       /* syn flag */
            20000,        /* window size */
            0x00,         /* checksum */
            0x00,         /* urg pointer */
            LIBNET_TCP_H, /* tcp header size */
            NULL,         /* payload */
            0x0000,       /* payload size */
            ltag, tcp
        );

        if ( tcp < 0 ) {
            sprintf(
                xscan_errbuf,
                "libnet_build_tcp(): %s", libnet_geterror( ltag )
            );
            return -1;
        }
    }
    // icmp scan
    if ( proto == IPPROTO_ICMP )
    {
        icmp = libnet_build_icmpv4_echo( ICMP_ECHO, 0, 0x00, irand, 0, NULL, 0x0000, ltag, icmp );
        if ( icmp < 0 ) {
            sprintf(
                xscan_errbuf,
                "libnet_build_icmpv4_echo(): %s", libnet_geterror( ltag )
            );
            return -1;
        }
    }

    ipv4 = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H, /* packet size */
        0,                            /* tos */
        irand,                        /* ip id */
        0x00,                         /* fragment offset */
        80,                           /* ttl */
        proto,                        /* protocol */
        0x00,                         /* checksum */
        inet_addr( src_ip ),          /* source ip */
        inet_addr( dst_ip ),          /* dest ip */
        NULL,                         /* payload */
        0x0000,                       /* payload size */
        ltag, ipv4
    );

    if ( ipv4 < 0 ) {
        sprintf(
            xscan_errbuf,
            "libnet_build_ipv4(): %s", libnet_geterror( ltag )
        );
        return -1;
    }
    return 0;
}

/* initialize the stats */
short __init_stats__( struct xp_stats *stats )
{
    if ( setup._host.subnet ) {
        stats->scan_ip = net_off( setup._host.ip, setup._host.subnet ); /* start ip address e.g 192.168.0.1 */
        stats->nhosts  = calc_nhosts( setup._host.subnet );
        stats->scan_ip++;
    } else {
        stats->nhosts  = 1;
        stats->scan_ip = IP2LB( setup._host.ip );
    }

    // calculate number of ports to scan
    if ( setup.type == X_SYN )
    {
        if ( setup._ports.range ) {
            stats->nports = setup._ports.end - setup._ports.start;
        } else {
            stats->nports = 1;
        }
        
        stats->scanned_ports = (SCPorts *) calloc( stats->nports + 1, sizeof( SCPorts ) );
        if ( !stats->scanned_ports ) {
            sprintf(
                xscan_errbuf,
                "%s: %s", __FILE__, "scanned_ports memory allocation error!\n"
            );
            return -1;
        }
        // total number of packets
        stats->tpkts = stats->nhosts * stats->nports;
    }
    
    // no ports
    if ( setup.type == X_ICMP ) {
        stats->nports = 0;
        // total number of packets
        stats->tpkts  = stats->nhosts * 1;
    }

    stats->hosts = (SCHosts *) calloc( stats->nhosts, sizeof( SCHosts ) );
    if ( !stats->hosts ) {
        sprintf(
            xscan_errbuf,
            "%s: %s", __FILE__, "SCHosts memory allocation error!\n"
        );
        // if we get to this point that means we have allocated memory
        // for the scanned_ports and we need to free it before return
        free( stats->scanned_ports );
        return -1;
    }

    for ( register uint16_t i = 0 ; i < stats->nhosts ; i++ )
    {
        LB2IP( stats->scan_ip, stats->hosts[i].ip );
        stats->hosts[i].id = IP2LB( stats->hosts[i].ip );
        stats->scan_ip++;
    }
    return 0;
}

short xscan_scan_host( struct xp_stats *stats, char *src_ip, char *dst_ip )
{
    short proto;
    short dd;
    short retv;
    char sbuff[500];
    uint16_t src_port, dst_port;
    struct libnet_stats lstat;
    
    memset( sbuff, '\0', sizeof( sbuff ) );
    switch ( setup.type ) {
        case X_SYN:
            src_port = 8000;
            dst_port = setup._ports.start;
            proto    = IPPROTO_TCP;
	    break;

	case X_ICMP:
            src_port = 0;
            dst_port = 0;
            proto    = IPPROTO_ICMP;
	    break;
    }
    dd = (stats->nports > 1 || stats->nports < 1) ? 1 : 0 ;

    for ( uint32_t i = 0 ; i < stats->nports + dd ; i++ ) {
        if ( (retv = xscan_init_packet( proto, src_ip, dst_ip, src_port, dst_port, sbuff )) < 0 ) {
            return -1;
        }

        if ( libnet_write( ltag ) < 0 ) {
            sprintf(
                xscan_errbuf,
                "xscan_scan_host(): %s", "Error writing packet!"
            );
            return -1;
        }
        libnet_clear_packet( ltag );
        libnet_stats( ltag, &lstat );
        
        if ( stats->nports > 1 ) {
            dst_port++;
        }
        stats->nsent = lstat.packets_sent;
        mssleep( 0.1 );
    }
    return 0;
}

// start the scan sniffer thread
short xscan_start_receiver( struct xp_stats *stats )
{
    int err;
    err = pthread_create( &thread, NULL, scan_sniffer, (void *) stats );
    if ( err ) {
        sprintf(
            xscan_errbuf,
            "Error spawning scan_sniffer thread!\n"
        );
        return -1;
    }
    #ifdef DEBUG
        v_out( VDEBUG, "%s: %s", __FILE__, "Spawned scan sniffer!\n" );
    #endif
    return 0;
}

void xscan_print_stats( struct xp_stats *stats )
{
    char *service;
    char state[10];
    uint16_t port;
    
    v_out( VINF, "Scan on host %s finished!\n", stats->current_host );
    switch ( setup.type ) {
        case X_SYN:
            stats->nclosed   = 0;
            stats->nopen     = 0;
            stats->nfiltered = 0;
            
            if ( setup._ports.range ) {
                for ( register uint16_t i = 0 ; i < stats->nports + 1 ; i++ )
                {
                    port = stats->scanned_ports[i].port;
                    switch ( stats->scanned_ports[i].state )
                    {
                        case XCLOSED:
                            strcpy( state, "closed" );
                            stats->nclosed++;
                            break;

                        case XOPEN:
                            strcpy( state, "open" );
                            stats->nopen++;
                            break;
                            
                        default:
                            strcpy( state, "filtered" );
                            stats->nfiltered++;
                            break;
                    }

                    service = portservice( port );
                    printf( "\t%s - %d - %s\n", service, port, state );
                }
                printf( "%d - %d - %d\n", stats->nclosed, stats->nopen, stats->nfiltered );
            } 
            else {
                port = setup._ports.start;
                switch ( stats->scanned_ports[0].state ) {
                    case XCLOSED:
                            strcpy( state, "closed" );
                            stats->nclosed++;
                            break;

                        case XOPEN:
                            strcpy( state, "open" );
                            stats->nopen++;
                            break;
                            
                        default:
                            strcpy( state, "filtered" );
                            stats->nfiltered++;
                            break;
                }
                service = portservice( port );
                printf( "\t%s - %d - %s\n", service, port, state );
                printf( "%d - %d - %d\n", stats->nclosed, stats->nopen, stats->nfiltered );
            }
            break;
        case X_ICMP:
            break;
    }
    v_ch( '\n' );
}

void __End__( int sig )
{
    libnet_clear_packet( ltag );
    libnet_destroy( ltag );
    xscan_free_stats( &stats );
    exit( 0 );
}

void xscan_free_stats( struct xp_stats *stats )
{
    free( stats->scanned_ports );
    free( stats->hosts );
}