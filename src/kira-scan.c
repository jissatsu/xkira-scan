#include "kira-scan.h"

void __xscan_initiate__( struct xp_stats *stats )
{
    if ( __init_stats__( stats ) < 0 ) {
        __die( "%s", xscan_errbuf );
    }

    LB2IP( stats->scan_ip, stats->current_host.ip );
    v_out( VINF, "Initiated SYN scan!\n" );
    v_out( VINF, "Scanning subnet - /%d\n", setup._host.subnet );
    v_out( VINF, "Starting from host [%s]\n", stats->current_host.ip );

    #ifdef DEBUG
        v_out( VDEBUG, "%s: Total hosts   -> %d\n", __FILE__, stats->nhosts );
        v_out( VDEBUG, "%s: Total ports   -> %d\n", __FILE__, stats->nports );
        v_out( VDEBUG, "%s: Total packets -> %d\n", __FILE__, stats->tpkts );
    #endif
    
    for ( uint32_t i = 0 ; i < stats->nhosts ; i++ )
    {
        stats->time = 0.0;
        LB2IP( stats->scan_ip, stats->current_host.ip );

        if ( xscan_scan_host( stats, setup.ip, stats->current_host.ip ) < 0 ) {
            // free all stats' allocated memory before dying
            xscan_free_stats( stats );
            __die( "%s", xscan_errbuf );
        }
        // delay between each host's scanning task
        mssleep( 0.4 );
        stats->scan_ip++;

        // calculate scanning progress
        stats->done = cpercent(
            (double) stats->tpkts, (double) stats->nsent
        );
        printf( "\rScanning progress - [%0.2lf%%]", stats->done );
        xscan_accum_stats( stats );
    }
    v_ch( '\n' );
}

/* Initialize the packet based on the protocol */
short xscan_init_packet( int proto, char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port )
{
    libnet_ptag_t tcp, icmp, ipv4;
    tcp = icmp = ipv4 = LIBNET_PTAG_INITIALIZER;
    // syn scan
    if ( proto == IPPROTO_TCP )
    {
        tcp = libnet_build_tcp(
            src_port,     /* source port */
            dst_port,     /* dest port */
            0x0000,       /* sequence number */
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
        icmp = libnet_build_icmpv4_echo( ICMP_ECHO, 0, 0x00, setup.pid, 0, NULL, 0x0000, ltag, icmp );
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
        setup.pid,                    /* ip id */
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

short xscan_scan_host( struct xp_stats *stats, char *src_ip, char *dst_ip )
{
    short proto;
    short dd;
    uint16_t src_port, dst_port;
    struct libnet_stats lstat;
    
    src_port = 0x00;
    dst_port = 0x00;
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

    // reset current host's state and port_resp
    xscan_reset_host( &stats->current_host );
    // send an icmp echo before the actual scanning in case the host is actually
    // up but has all ports filtered (which means that we won't receive any replies)
    if ( xscan_send_packet( IPPROTO_ICMP, setup.ip, dst_ip, 0x00, 0x00 ) < 0 ) {
        return -1;
    }

    for ( uint32_t i = 0 ; i < stats->nports + dd ; i++ ) {
        if ( setup._ports.start ) {
            // set the current scan port state to default `0` (filtered)
            // if its actually not filtered it will be later set by
            // the scan receiver to either 1 (open) or 2 (closed)
            stats->current_host.ports[i].state = 0;
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

void xscan_accum_stats( struct xp_stats *stats )
{
    short pstat;
    // host is not up
    if ( !stats->current_host.state ) {
        #ifdef DEBUG
            v_out(
                VWARN,
                "Host [%s] is either down or behind a firewall!\n",
                stats->current_host.ip
            );
        #endif
        // push host to the `down` list
        pstat = xscan_push_host(
            XDOWN,
            stats->current_host
        );

        if ( pstat < 0 ) {
            __die( "%s", xscan_errbuf );
        }
        return;
    }

    // host is up, but has all scan ports filtered
    if ( stats->current_host.state && !stats->current_host.port_resp )
    {
        // push host to the `filtered` list
        #ifdef DEBUG
            v_out(
                VWARN,
                "Host [%s] has ports %d - %d filtered!\n",
                stats->current_host.ip,
                setup._ports.start,
                setup._ports.end
            );
        #endif
        pstat = xscan_push_host(
            XFILTERED,
            stats->current_host
        );

        if ( pstat < 0 ) {
            __die( "%s", xscan_errbuf );
        }
    } else {
        // push host to the `up` list
        #ifdef DEBUG
            v_out(
                VWARN,
                "Host [%s] doesn't have all ports filtered!\n",
                stats->current_host.ip
            );
        #endif
        pstat = xscan_push_host(
            XACTIVE,
            stats->current_host
        );

        if ( pstat < 0 ) {
            __die( "%s", xscan_errbuf );
        }
    }
    v_ch( '\n' );
}

short xscan_push_host( xstate_t state, SCHost host )
{
    SChosts *push_loc;

    switch ( state ) {
        case XDOWN:
            // down hosts buffer
            push_loc = &stats.scanned_hosts[1];
            if ( xscan_set_pushbuff( push_loc, host, stats.ndown, stats.ndown + 2 ) < 0 ) {
                return -1;
            }
            ++stats.ndown;
            break;

        case XFILTERED:
            // filtered hosts buffer
            push_loc = &stats.scanned_hosts[2];
            if ( xscan_set_pushbuff( push_loc, host, stats.nfiltered, stats.nfiltered + 2 ) < 0 ) {
                return -1;
            }
            ++stats.nfiltered;
            break;
            
        case XACTIVE:
            // active hosts buffer
            push_loc = &stats.scanned_hosts[0];
            if ( xscan_set_pushbuff( push_loc, host, stats.nactive, stats.nactive + 2 ) < 0 ) {
                return -1;
            }
            ++stats.nactive;
            break;
    }
    return 0;
}

// set the push buffer and expand it for the next item
short xscan_set_pushbuff( SChosts *push_loc, SCHost host, uint16_t offset, uint16_t newsize )
{
    push_loc->buffer[offset] = (SCHost *) calloc( 1, sizeof( SCHost ) );
    if ( !push_loc->buffer[offset] ) {
        sprintf(
            xscan_errbuf, 
            "%s - %d", strerror( errno ),
            __LINE__
        );
        return -1;
    }

    // allocate memory for the ports
    push_loc->buffer[offset]->ports = (SCPorts *) calloc( stats.nports + 1, sizeof( SCPorts ) );
    if ( !push_loc->buffer[offset]->ports ) {
        sprintf(
            xscan_errbuf, 
            "%s - %d", strerror( errno ),
            __LINE__
        );
        return -1;
    }
    
    // expand the current buffer
    push_loc->buffer = xscan_expand_buff( push_loc->buffer, newsize );
    if ( !push_loc->buffer ) {
        return -1;
    }

    // set the next location in the buffer to NULL
    push_loc->buffer[offset + 1] = NULL;
    xscan_copy_buff( push_loc->buffer[offset], &host );
    return 0;
}

// expands buffer
// sets `xscan_errbuf` on error and returns -1
SCHost ** xscan_expand_buff( SCHost **buff, size_t size )
{
    SCHost **newbuf;

    newbuf = (SCHost **) realloc( buff, size * sizeof( SCHost * ) );
    if ( !newbuf ) {
        sprintf(
            xscan_errbuf,
            "%s - %d", strerror( errno ), __LINE__
        );
        return NULL;
    }
    return newbuf;
}

void xscan_copy_buff( SCHost *dbuff, const SCHost *sbuff )
{
    uint16_t nports;

    if ( stats.nports > 1 ) {
        nports = stats.nports + 1;
    } else {
        nports = stats.nports;
    }

    memcpy( dbuff->ip, sbuff->ip, strlen( sbuff->ip ) + 1 );
    dbuff->ip[-1]    = '\0';
    dbuff->nclosed   = sbuff->nclosed;
    dbuff->nopen     = sbuff->nopen;
    dbuff->nfiltered = nports - (sbuff->nclosed + sbuff->nopen);
    memcpy(
        dbuff->ports, sbuff->ports,
        (stats.nports + 1) * sizeof( SCPorts )
    );
}

void xscan_reset_host( SCHost *current_host )
{
    current_host->state     = 0x00;
    current_host->port_resp = 0x00;
    current_host->nclosed   = 0x00;
    current_host->nopen     = 0x00;
    current_host->nfiltered = 0x00;
}

void __End__( int sig )
{
    libnet_clear_packet( ltag );
    libnet_destroy( ltag );
    xscan_free_stats( &stats );
    exit( 0 );
}