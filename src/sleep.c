#include "sleep.h"

void mssleep( float nsec )
{
    struct timespec t1;
    struct timespec t2;

    t1.tv_nsec = nsec * 1000000000L;
    t1.tv_sec  = 0;
    
    nanosleep( &t1, &t2 );
}