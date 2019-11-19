#include "kira-scan.h"

struct args * xscan_parse_options( int argc, char **argv,
                                   void (*usage)(char *))
{
    int opt;
    static struct args _args;
    
    while ( (opt = getopt( argc, argv, "i:t:d:p:v" )) != -1 ) {
        switch ( opt ) {
            case 't':
                _args.type  = optarg;
                break;
            case 'd':
                _args.host  = optarg;
                break;
            case 'p':
                _args.ports = optarg;
                break;
            case 'i':
                _args.iface = optarg;
                break;
            case 'v':
                _args.verbose = 1;
                break;
            default:
                usage( argv[0] );
        }
    }

    if ( !_args.host || !_args.type || !_args.iface ) {
        usage( argv[0] );
    }
    return &_args;
}


short __xscan_init__( struct args *args, struct xp_setup *setup )
{
    memset( setup, '\0', sizeof( struct xp_setup ) );

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
        printf( "[Debug]\n" );
        printf( "%s: setup->type -> %d\n", __FILE__, setup->type );
        printf( "%s: Setup->on: %d\n", __FILE__, setup->on );
        printf( "Host name -> %s\n", setup->_host.name );
        printf( "Host ip   -> %s\n", setup->_host.ip );
        printf( "Our ip    -> %s\n\n", setup->ip );
    #endif
    return 0;
}


void __xscan_initiate__( struct xp_stats *stats,
                         void (*shandler)(struct xp_stats *stats) )
{
    int sock;
    int hdrincl;
    char *prt = NULL;
    char sbuff[400], rbuff[400];
    struct protoent *proto;
    struct xp_packet pkt;
    struct sockaddr_in dst_addr;

    if ( (sock = socket( AF_INET, SOCK_RAW, IPPROTO_RAW )) < 0 ) {
        perror( "Error: " );
        exit( 1 );
    }

    dst_addr.sin_family      = AF_INET;
    dst_addr.sin_port        = htons( 80 );
    dst_addr.sin_addr.s_addr = inet_addr( "216.58.206.174" );

    sockopt_hdrincl( &sock, &hdrincl );
    stats->nrecv =   0;
    stats->nsent =   0;
    stats->tpkts =   0;
    stats->time  = 0.0;
    memset( sbuff, '\0', sizeof( sbuff ) );

    switch ( setup.type ) {
        case X_ICMP:
            prt = "icmp";
            break;
        case X_SYN:
            prt = "tcp";
            break;
    }
    proto = getprotobyname( prt );

    // build ipv4 header if include-header option was set successfully
    if ( hdrincl ) {
        if ( !(pkt.ip = xscan_build_ipv4( proto->p_proto, setup.pid, setup.ip, setup._host.ip, 0, sbuff )) ) {
            __die( "%s", "Error building IPV4 header!\n" );
        }
    }

    if ( setup.type == X_ICMP ) {
        if ( !(pkt.icmp = xscan_build_icmp( ICMP_ECHO, setup.pid, 0, sbuff )) ) {
            __die( "%s", "Error building ICMP header!\n" );
        }   
    }

    if ( setup.type == X_SYN ) {
        //if ( !(pkt.tcp = xscan_build_tcp( (char *) {0, 0, 0, 0, 0, 0, 0, 1, 0}, rand_port, 80 sbuff )) ) {
        //    __die( "%s", "Error building TCP header!\n" );
        //}
    }

    /* printf( "ICMP TYPE  -> %d\n", pkt.icmp->icmp_type );
    printf( "ICMP CODE  -> %d\n", pkt.icmp->icmp_code );
    printf( "ICMP ID    -> %d\n", pkt.icmp->icmp_id );
    printf( "ICMP SEQ   -> %d\n", pkt.icmp->icmp_seq );
    printf( "ICMP CKSUM -> %d\n\n", pkt.icmp->icmp_cksum );

    printf( "IPV4 IHL   -> %d\n", pkt.ip->ip_hl );
    printf( "IPV4 VER   -> %d\n", pkt.ip->ip_v );
    printf( "IPV4 TOS   -> %d\n", pkt.ip->ip_tos );
    printf( "IPV4 LEN   -> %d\n", ntohs( pkt.ip->ip_len ) );
    printf( "IPV4 ID    -> %d\n", ntohs( pkt.ip->ip_id ) );
    printf( "IPV4 TTL   -> %d\n", pkt.ip->ip_ttl );
    printf( "IPV4 PROTO -> %d\n", pkt.ip->ip_p );
    printf( "IPV4 SUM   -> %d\n", pkt.ip->ip_sum );
    // xscan_send_packet( pkt, setup._host.ip ); */

    int nbytes;
    if ( (nbytes = sendto( sock, sbuff, sizeof( sbuff ), 0, (struct sockaddr *) &dst_addr, sizeof( dst_addr ) )) ) {
        printf( "%d\n", nbytes );
    }
    return;
}

// start the scan sniffer thread
short xscan_start_sniffer( struct xp_stats *stats )
{
    int err;
    pthread_t thread;
    
    err = pthread_create(
        &thread,
        NULL,
        scan_sniffer,
        (void *) stats
    );

    if ( err ) {
        sprintf(
            xscan_errbuf,
            "Error spawning scan_sniffer thread!\n"
        );
        return -1;
    }
    return 0;
}

short xscan_validate_ports( struct ports *ports )
{
    switch ( ports->range ) {
        // no port range
        case 0:
            #ifdef DEBUG
                printf( "[Debug]\n" );
                printf( "%s: Ports -> %d - %d\n\n", __FILE__, ports->start, ports->end );
            #endif
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
            #ifdef DEBUG
                printf( "[Debug]\n" );
                printf( "%s: Ports -> %d - %d\n\n", __FILE__, ports->start, ports->end );
            #endif
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
    setup->_host.name = NULL;

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

void __End__( int sig )
{
    return;
}