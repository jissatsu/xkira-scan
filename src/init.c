#include "init.h"

short __xscan_init__( struct args *args, struct xp_stats *stats,
                      struct xp_setup *setup )
{
    memset( setup, '\0', sizeof( struct xp_setup ) );
    memset( stats, 0, sizeof( struct xp_stats ) );

    // check if output goes to the terminal
    if ( isatty( 1 ) && isatty( 2 ) ) {
        setup->tty = 1;
    }
    o_set_tty( setup->tty );

    if ( strcmp( args->type, "icmp" ) != 0 && 
         strcmp( args->type, "syn" )  != 0 ) {
             sprintf( xscan_errbuf, "Invalid scan type!" );
             return -1;
    }

    if ( strcmp( args->type, "icmp" ) == 0 ) {
        if ( args->ports ) {
            sprintf(
                xscan_errbuf,
                "Can't use ICMP for port scanning... Use SYN instead!"
            );
            return -1;
        }
        setup->type = X_ICMP;
    } else {
        if ( !args->ports ) {
            sprintf(
                xscan_errbuf,
                "No port or port-range specified for SYN scan!"
            );
            return -1;
        }
        setup->type = X_SYN;
    }

    if ( args->ports ) {
        if ( xscan_set_ports( args->ports, &(setup->_ports) ) != 0 ) {
            sprintf(
                xscan_errbuf,
                "Invalid port argument!"
            );
            return -1;
        }

        if ( xscan_validate_ports( &(setup->_ports) ) != 0 ) {
            sprintf(
                xscan_errbuf,
                "Invalid port argument!"
            );
            return -1;
        }
    }
    
    if ( xscan_hostinfo( args->host, setup ) != 0 ){
        sprintf(
            xscan_errbuf,
            "Invalid host argument!"
        );
        return -1;
    }

    if ( net_ip( args->iface, setup->ip ) < 0 ) {
        return -1;
    }

    setup->pid = getpid();
    setup->verbose = args->verbose;
    
    // range scan (scan a subnet or multiple ports)
    if ( setup->_host.subnet || setup->_ports.range ) {
        setup->on = 1;
    }
    #ifdef DEBUG
        v_out( VDEBUG, "%s: %s -> %d\n",   __FILE__, "Setup->type", setup->type );
        v_out( VDEBUG, "%s: %s -> %d\n",   __FILE__, "Setup->on",   setup->on );
        v_out( VDEBUG, "%s: %s -> %s\n",   __FILE__, "Host name",   setup->_host.name );
        v_out( VDEBUG, "%s: %s -> %s\n",   __FILE__, "Host ip",     setup->_host.ip );
        v_out( VDEBUG, "%s: %s -> %s\n\n", __FILE__, "Our ip",      setup->ip );
    #endif
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