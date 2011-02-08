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

void add_time(struct timeval *now, time_t secs,  suseconds_t usecs);
void set_timeval(struct timeval *target, struct timeval *val);
inline int time_diff(struct timeval *now, struct timeval *then);

void* xmalloc(size_t len);

void fail(const char *msg);

/**
 * Endiannes change for 64 bit numbers. 
 */
uint64_t ntohll(uint64_t val);
uint16_t ip_sum_calc(uint16_t len_ip_header, uint16_t buff[]);

#endif
