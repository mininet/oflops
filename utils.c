#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <arpa/inet.h>

#include <net/ethernet.h>
#include <net/if_arp.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include <sys/time.h>

#include "utils.h"

/****************************************************************
 * shouldn't this be a in libc?  I mean... come on...
 */

void * _realloc_and_check(void * ptr, size_t bytes, char * file, int lineno)
{
	void * ret = realloc(ptr,bytes);
	if(!ret)
	{
		perror("malloc/realloc: ");
		// use fprintf here in addition to flowvisor_err, incase we can't allocate the err msg buf
		fprintf(stderr, "Malloc/Realloc(%zu bytes) failed at %s:%d\n",bytes,file,lineno);
		abort();
	}
	return ret;
}


/***************************************************************
 * print errno and exit
 */

void perror_and_exit(char * str, int exit_code)
{
	perror(str);
	exit(exit_code);
}

void 
set_timeval(struct timeval *target, struct timeval *val) {
  target->tv_sec = val->tv_sec;
  target->tv_usec = val->tv_usec;
}

void
add_time(struct timeval *now, time_t secs,  suseconds_t usecs) {
  const uint64_t sec_to_usec = 1000000;
  now->tv_sec += secs;
  now->tv_usec += usecs;
  if(now->tv_usec > sec_to_usec) {
    now->tv_sec += 1; 
    now->tv_usec -= sec_to_usec; 
  }
}

inline int
time_diff(struct timeval *now, struct timeval *then) {
  return (then->tv_sec - now->tv_sec)*1000000 + (then->tv_usec - now->tv_usec);
}

void*
xmalloc(size_t len) {
  void *p = NULL;
  p = malloc(len);
  if (p == NULL)
    fail("Failed while allocating memmory");
  return p;
}

void 
fail(const char * msg) {
  printf("error: %s\n", msg);
  exit(1);
}

uint64_t
ntohll(uint64_t val) {
  uint64_t ret = 0;
    
  ret=((val & 0x00000000000000FF) << 56) |
    ((val & 0x000000000000FF00) << 40) |
    ((val & 0x0000000000FF0000) << 24) |
    ((val & 0x00000000FF000000) << 8)  |
    ((val & 0x000000FF00000000) >> 8)  | 
    ((val & 0x0000FF0000000000) >> 24) |
    ((val & 0x00FF000000000000) >> 40) |
    ((val & 0xFF00000000000000) >> 56);

  return ret;
}

uint16_t ip_sum_calc(uint16_t len_ip_header, uint16_t buff[]) {
  uint16_t word16;
  uint32_t sum=0;
  uint16_t i;
  
  // make 16 bit words out of every two adjacent 8 bit words in the packet
  // and add them up
  for (i=0;i<len_ip_header;i=i+2){
    word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
    sum = sum + (uint32_t) word16;	
  }
  
  // take only 16 bits out of the 32 bit sum and add up the carries
  while (sum>>16)
    sum = (sum & 0xFFFF)+(sum >> 16);
  
  // one's complement the result
  sum = ~sum;
  
  return ((uint16_t) sum);
}
