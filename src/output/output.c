#include "output.h"

// output/output.c
void o_set_tty( short _tty )
{
    tty = _tty;
}

// output/output.c
void v_ch( char c )
{
    putchar( c );
}

// output/output.c
void __die( char *format, ... )
{
    char msgf[0xFF];
    va_list list;
    
    va_start( list, format );
    vsprintf( msgf, format, list );
    v_out( VERR, "%s", msgf );
    exit( 1 );
}

// output/output.c
void v_out( vmsg_t type, char *format, ... )
{   
    char *c1, *c2, *pfx;
    char msgf[0xFF];
    va_list list;
    
    c2  = (tty) ? NLL : "" ;
    if ( type == VINF )  c1 = (tty) ? GRN : "", pfx = "[INFO] -";
    if ( type == VWARN ) c1 = (tty) ? YLL : "", pfx = "[WARN] -";
    if ( type == VERR )  c1 = (tty) ? RED : "", pfx = "[ERROR] -";
    // no msg type
    if ( type == NVVV )  c1 = "", pfx = "";

    va_start( list, format );
    vsprintf( msgf, format, list );
    printf( "%s%s%s %s", c1, pfx, c2, msgf );
}