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
        xscan_reset_stats( stats );
        if ( xscan_scan_host( stats, setup.ip, stats->hosts[i].ip ) < 0 ) {
            // free all stats' allocated memory
            xscan_free_stats( stats );
            __die( "%s", xscan_errbuf );
        }

        stats->current_host = stats->hosts[i].ip;
        if ( setup.verbose )
        {
            stats->done = cpercent( (double) stats->tpkts, (double) stats->nsent );
            printf( "[%0.2lf%%]\n", stats->done );
            xscan_print_stats( stats );
        }
    }
}

/* Initialize the packet based on the protocol */
short xscan_init_packet( int proto, char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port )
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

short xscan_send_packet( short proto, char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port )
{
    if ( xscan_init_packet( proto, src_ip, dst_ip, src_port, dst_port ) < 0 ) {
        return -1;
    }

    if ( libnet_write( ltag ) < 0 ) {
        sprintf(
            xscan_errbuf,
            "xscan_send_packet(): %s", "Error writing packet!"
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

    // calculate number of ports and packets to scan
    if ( setup.type == X_SYN )
    {
        if ( setup._ports.range ) {
            stats->nports = setup._ports.end - setup._ports.start;
        } else {
            stats->nports = 1;
        }
        
        if ( __xscan_init_ports__( stats ) < 0 ) {
            return -1;
        }
        // total number of packets
        stats->tpkts = stats->nhosts * (stats->nports + 1);
    }
    
    // no ports
    if ( setup.type == X_ICMP ) {
        stats->nports = 0;
        // total number of packets
        stats->tpkts  = stats->nhosts * 1;
    }

    if ( __xscan_init_hosts__( stats ) < 0 ) {
        free( stats->scanned_ports );
        return -1;
    }
    return 0;
}

/* initialize the scanned_ports (SCPorts) struct array */
short __xscan_init_ports__( struct xp_stats *stats )
{
    stats->scanned_ports = (SCPorts *) calloc( stats->nports + 1, sizeof( SCPorts ) );
    if ( !stats->scanned_ports ) {
        sprintf(
            xscan_errbuf,
            "%s: %s", __FILE__, "scanned_ports memory allocation error!\n"
        );
        return -1;
    }

    if ( stats->nports == 1 ) {
        stats->scanned_ports[0].port = setup._ports.start;
        return 0;
    }
    
    for ( register uint16_t i = 0 ; i < stats->nports + 1 ; i++ ) {
        stats->scanned_ports[i].port = setup._ports.start + i;
    }
    return 0;
}

/* initialize the hosts (SCHosts) struct array */
short __xscan_init_hosts__( struct xp_stats *stats )
{
    stats->hosts = (SCHosts *) calloc( stats->nhosts, sizeof( SCHosts ) );
    if ( !stats->hosts ) {
        sprintf(
            xscan_errbuf,
            "%s: %s", __FILE__, "SCHosts memory allocation error!\n"
        );
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
    uint16_t src_port, dst_port;
    struct libnet_stats lstat;
    
    src_port = 0;
    dst_port = 0;
    dd       = (stats->nports > 1 || stats->nports < 1) ? 1 : 0 ;
    
    switch ( setup.type ) {
        case X_SYN:
            src_port = 8000;
            dst_port = setup._ports.start;
            proto    = IPPROTO_TCP;
	    break;

	default:
        proto = IPPROTO_ICMP;
	    break;
    }

    for ( uint32_t i = 0 ; i < stats->nports + dd ; i++ ) {
        if ( setup._ports.start ) {
            // set the current scan port state to default `0` (filtered)
            // if its actually not filtered it will be later set by
            // the scan receiver to either 1 (open) or 2(closed)
            stats->scanned_ports[i].state = 0;
        }
        if ( xscan_send_packet( proto, src_ip, dst_ip, src_port, dst_port ) < 0 ) {
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
    char *state;
    uint16_t port;
    
    stats->nfiltered = (stats->nports + 1) - (stats->nopen + stats->nclosed);
    v_out( VINF, "[%s]\n", stats->current_host );
    v_out( VINF, "%d closed ports\n", stats->nclosed );
    v_out( VINF, "%d open ports\n", stats->nopen );
    v_out( VINF, "%d filtered ports\n", stats->nfiltered );

    switch ( setup.type )
    {
        case X_SYN:
            if ( setup._ports.range )
            {
                if ( !stats->nopen && !stats->nclosed ) {
                    v_out(
                        VWARN, "Host is either down or has ports [%d - %d] filtered!\n",
                        setup._ports.start,
                        setup._ports.end
                    );
                    break;
                }
                printf( "\n\t[PORT]  [SERVICE]  [STATE]\n" );
                for ( register uint16_t i = 0 ; i < stats->nports + 1 ; i++ )
                {
                    state   = xscan_portstate_expl( stats->scanned_ports[i].state );
                    port    = stats->scanned_ports[i].port;
                    service = portservice( port );
                    printf( "\t%-7d  %-8s  %s\n", port, service, state );
                }
            }
            
            if ( !setup._ports.range )
            {
                printf( "\n\t[PORT]  [SERVICE]  [STATE]\n" );
                state   = xscan_portstate_expl( stats->scanned_ports[0].state );
                port    = setup._ports.start;
                service = portservice( port );
                printf( "\t%-7d  %-8s  %s\n", port, service, state );
            }
            break;
        case X_ICMP:
            break;
    }
    v_ch( '\n' );
}

char * xscan_portstate_expl( port_t state )
{
    static char state_expl[10];
    switch ( state ) {
        case XCLOSED:
            strcpy( state_expl, "closed" );
            break;

        case XOPEN:
            strcpy( state_expl, "open" );
            break;

        default:
            strcpy( state_expl, "filtered" );
            break;
    }
    return state_expl;
}

void xscan_reset_stats( struct xp_stats *stats )
{
    stats->nclosed   = 0;
    stats->nopen     = 0;
    stats->nfiltered = 0;
    stats->time      = 0.0;

    //for ( register uint16_t i = 0 ; i < stats->nports + 1 ; i++ ) {
    //    stats->scanned_ports[i].state = 0;
    //}
    // memset( stats->scanned_ports, 0, (stats->nports + 1) * sizeof( SCPorts ) );
}

double cpercent( double total, double frac )
{
    return (double) (frac / total) * 100;
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