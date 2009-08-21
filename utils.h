#ifndef UTILS_H
#define UTILS_H

#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>


#include <sys/types.h>


// sigh.. why is this not defined in some standard place
#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif
#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

#ifndef BUFLEN
#define BUFLEN 4096
#endif

#define malloc_and_check(x) _realloc_and_check(NULL,(x),__FILE__,__LINE__);
#define realloc_and_check(ptr,x) _realloc_and_check((ptr),(x),__FILE__,__LINE__);
void * _realloc_and_check(void * ptr,size_t bytes, char * file, int lineno);

void perror_and_exit(char * str, int exit_code);


#endif
