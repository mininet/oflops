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
