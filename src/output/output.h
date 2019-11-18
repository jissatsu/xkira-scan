#ifndef __OUTPUT_H
#define __OUTPUT_H 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include "color.h"

#ifdef __cplusplus
extern "C"{
#endif

short tty;

typedef enum { NVVV, VERR, VINF, VWARN } vmsg_t;

void  o_set_tty( short _tty );
void  v_ch( char c );
void __die( char *format, ... );
void  v_out( vmsg_t type, char *format, ... );

#ifdef __cplusplus
}
#endif

#endif