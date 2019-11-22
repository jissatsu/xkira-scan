#ifndef __SLEEP_H
#define __SLEEP_H

#ifndef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 199309L
#endif
#include <time.h>
void mssleep( float nsec );

#endif
