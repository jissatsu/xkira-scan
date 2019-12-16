#include "init.h"

short __xscan_init__( struct args *args, struct xp_stats *stats )
{
    memset( &setup, '\0', sizeof( struct xp_setup ) );
    memset( stats, 0, sizeof( struct xp_stats ) );

    // check if output goes to the terminal
    if ( isatty( 1 ) ) {
        setup.tty = 1;
    }
    o_set_tty( setup.tty );

    if ( !args->ports ) {
        sprintf(
            xscan_errbuf,
            "No port or port-range specified for SYN scan!"
        );
        return -1;
    }

    if ( xscan_set_ports( args->ports, &(setup._ports) ) != 0 ) {
        sprintf(
            xscan_errbuf,
            "Invalid port argument!"
        );
        return -1;
    }

    if ( xscan_validate_ports( &(setup._ports) ) != 0 ) {
        sprintf(
            xscan_errbuf,
            "Invalid port argument!"
        );
        return -1;
    }
    
    if ( xscan_hostinfo( args->host, &setup ) != 0 ) {
        sprintf(
            xscan_errbuf,
            "Invalid host argument!"
        );
        return -1;
    }

    // get the ip and name of the first active device
    if ( net_ip( setup.iface, setup.ip ) < 0 ) {
        return -1;
    }
    
    // initialize libnet
    if ( (ltag = libnet_init( LIBNET_RAW4, setup.iface, xscan_errbuf )) == NULL ) {
        return -1;
    }

    setup.pid = getpid();
    // range scan (scan a subnet or multiple ports)
    if ( setup._host.subnet || setup._ports.range ) {
        setup.on = 1;
    }
    #ifdef DEBUG
        v_out( VDEBUG, "%s: %s -> %d\n",   __FILE__, "Setup->on",     setup.on );
        v_out( VDEBUG, "%s: %s -> %s\n",   __FILE__, "Host name",     setup._host.name );
        v_out( VDEBUG, "%s: %s -> %s\n",   __FILE__, "Host ip",       setup._host.ip );
        v_out( VDEBUG, "%s: %s -> %s\n",   __FILE__, "Our ip",        setup.ip );
        v_out( VDEBUG, "%s: %s -> %s\n\n", __FILE__, "Our interface", setup.iface );
    #endif
    return 0;
}

/* initialize the stats */
short __init_stats__( struct xp_stats *stats )
{
    if ( __xscan_init_buffs__( stats ) < 0 ) {
        return -1;
    }

    if ( setup._host.subnet )
    {
        stats->scan_ip = net_off( setup._host.ip, setup._host.subnet ); /* start ip address e.g 192.168.0.1 */
        stats->nhosts  = calc_nhosts( setup._host.subnet );
        stats->scan_ip++;
    } else {
        stats->nhosts  = 1;
        stats->scan_ip = IP2LB( setup._host.ip );
    }

    // calculate number of ports and packets to scan
    if ( setup._ports.range )
    {
        stats->nports = setup._ports.end - setup._ports.start;
        // total number of packets
        // multiply by 2 because of the additional icmp probe
        stats->tpkts = (stats->nhosts * stats->nports ) + (stats->nhosts * 2);
    } else {
        stats->nports = 1;
        // here we add `stats->nhosts` at the end because of the additional icmp probe
        stats->tpkts = (stats->nhosts * stats->nports ) + stats->nhosts;
    }
    
    if ( __xscan_init_ports__( stats ) < 0 ) {
        return -1;
    }
    return 0;
}

short __xscan_init_buffs__( struct xp_stats *stats )
{
    char *buffs[3] = {
        "other",
        "down",
        "filtered"
    };
    stats->scanned_hosts = (SChosts *) calloc( XSCAN_NBUFFERS, sizeof( SChosts ) );
    if ( !stats->scanned_hosts ) {
        sprintf(
            xscan_errbuf,
            "%s", strerror( errno )
        );
        return -1;
    }

    for ( register short i = 0 ; i < XSCAN_NBUFFERS ; i++ )
    {
        stats->scanned_hosts[i].buffer = (SCHost **) calloc( 1, sizeof( SCHost * ) );
        if ( !stats->scanned_hosts[i].buffer ) {
            sprintf(
                xscan_errbuf,
                "%s", strerror( errno )
            );
            return -1;
        }
        stats->scanned_hosts[i].buffer[0] = NULL;
        strcpy( stats->scanned_hosts[i].type, buffs[i] );
    }
    return 0;
}

// initialize the current_host ports array
short __xscan_init_ports__( struct xp_stats *stats )
{
    stats->current_host.ports = (SCPorts *) calloc( stats->nports + 1, sizeof( SCPorts ) );
    if ( !stats->current_host.ports ) {
        sprintf(
            xscan_errbuf,
            "%s: %s",
            __FILE__,
            "current_host.ports memory allocation error!\n"
        );
        return -1;
    }
    #ifdef DEBUG
        v_out( VDEBUG, "%s: %s\n", __FILE__, "current_host.ports alloc success!" );
    #endif

    if ( stats->nports == 1 ) {
        stats->current_host.ports[0].port = setup._ports.start;
        return 0;
    }
    
    for ( register uint16_t i = 0 ; i < stats->nports + 1 ; i++ ) {
        stats->current_host.ports[i].port = setup._ports.start + i;
    }
    return 0;
}

short xscan_validate_ports( struct ports *ports )
{
    switch ( ports->range ) {
        // no port range
        case 0:
            if ( ports->start < 1 || ports->start > 65535 ) {
                sprintf(
                    xscan_errbuf,
                    "Invalid port argument!"
                );
                return -1;
            }
            break;
        // port range in use
        case 1:
            if ( (ports->start >= ports->end) ||                // start port is >= end port
                 (ports->start > 65535 || ports->end > 65535 )  // any of the ports is > 65535
             ) {
                 sprintf(
                    xscan_errbuf,
                    "Invalid port argument!"
                );
                return -1;
            }
            break;
    }
    #ifdef DEBUG
        v_out( VDEBUG, "%s: Ports -> %d - %d\n", __FILE__, ports->start, ports->end );
    #endif
    return 0;
}

short xscan_set_ports( const char *p, struct ports *ports )
{
    int port;
    int is_r;
    int range[2];
    register int i, j;
    char tok[20];
    
    // check if it's a single port or a port range
    is_r = strstr( p, "-" ) ? 1 : 0 ;

    // single port
    if ( !is_r ) {
        port = atoi( p );
        ports->start = (port >= 1 && port <= 65535) ? port : 0 ;
        ports->range = 0;
        return 0;
    }

    // port range
    if ( is_r ) {

        i = 0;
        j = 0;
        while ( *p != '\0' )
        {
            if ( *p == '-' ) {
                tok[i] = '\0', range[j++] = atoi( tok ), i = 0, ++p;
            } else {
                tok[i++] = *p++;
            }
        }
        tok[i]   = '\0';
        range[j] = atoi( tok );

        ports->start = range[0];
        ports->end   = range[1];
        ports->range = 1;
        return 0;
    }
    return -1;
}

short xscan_hostinfo( char *host, struct xp_setup *setup )
{
    int subnet;
    char *ip, *sub;
    struct in_addr addr;
    struct hostent *hp;

    ip = is_ip( host );
    setup->_host.name   = NULL;
    setup->_host.subnet = 0;

    if ( ip )
    {
        if( inet_aton( ip, &addr ) ) {
            hp = gethostbyaddr( (const void *) &addr, sizeof( addr ), AF_INET );
            if ( hp )
            {
                setup->_host.name = hp->h_name;
            }
        }
        setup->_host.ip = ip;
        
        // subnet parsing
        sub = strchr( host, '/' );
        if ( sub )
        {
            subnet = atoi( ++sub );
            if ( subnet < 16 || subnet > 30 ) {
                return -1;
            }
            setup->_host.subnet = subnet;
        }
    }

    // if it's not an ip address assume it's a host name e.g www.google.com
    if ( !ip )
    {
        hp = gethostbyname( host );
        if ( !hp ) {
            return -1;
        }
        setup->_host.name = host;
        setup->_host.ip   = inet_ntoa( *(struct in_addr *) hp->h_addr_list[0] );
    }
    return 0;
}