#include "xscan_str.h"

char * xsc_upper( const char *str )
{
    register size_t i, len;
    char *upper;
    
    if ( (len = strlen( str )) <= 0 ) {
        return NULL;
    }

    upper = (char *) malloc( len + 1 );
    if ( !upper ) {
        return NULL;
    }

    i = 0;
    while ( *str != '\0' ) {
        upper[i++] = (*str >= 'a' && *str <= 'z') ? *str - 32 : *str ;
        str++;
    }
    upper[i] = '\0';
    return upper;
}