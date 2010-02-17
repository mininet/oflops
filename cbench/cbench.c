#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <netinet/tcp.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>


#include <openflow/openflow.h>

#include "cbench.h"
#include "fakeswitch.h"


int run_test(int n_fakeswitches, struct fakeswitch * fakeswitches)
{
    struct timeval now, then, diff;
    struct  pollfd  * pollfds;
    int i;
    double sum = 0;
    double passed;
    int count;

    pollfds = malloc(n_fakeswitches * sizeof(struct pollfd));
    assert(pollfds);
    gettimeofday(&then,NULL);
    while(1)
    {
        gettimeofday(&now, NULL);
        timersub(&now, &then, &diff);
        if( diff.tv_sec > 0)
            break;
        for(i = 0; i< n_fakeswitches; i++)
            fakeswitch_set_pollfd(&fakeswitches[i], &pollfds[i]);

        poll(pollfds, n_fakeswitches, -1);      // block until something is ready

        for(i = 0; i< n_fakeswitches; i++)
            fakeswitch_handle_io(&fakeswitches[i], &pollfds[i]);
    }
    printf("%-3d switches: fmods/sec:  ", n_fakeswitches);
    for( i = 0 ; i < n_fakeswitches; i++)
    {
        count = fakeswitch_get_count(&fakeswitches[i]);
        printf("%d  ", count);
        sum += count;
    }
    passed = 1000 * diff.tv_sec + diff.tv_usec/1000;   
    sum /= passed;  // is now per ms
    printf(" total = %lf per ms \n", sum);
    free(pollfds);
    return 0;
}

/********************************************************************************/

int timeout_connect(int fd, const char * hostname, int port, int mstimeout) {
	int ret = 0;
	int flags;
	fd_set fds;
	struct timeval tv;
	struct addrinfo *res=NULL;
	struct addrinfo hints;
	char sport[BUFLEN];
	int err;

	hints.ai_flags          = 0;
	hints.ai_family         = AF_INET;
	hints.ai_socktype       = SOCK_STREAM;
	hints.ai_protocol       = IPPROTO_TCP;
	hints.ai_addrlen        = 0;
	hints.ai_addr           = NULL;
	hints.ai_canonname      = NULL;
	hints.ai_next           = NULL;

	snprintf(sport,BUFLEN,"%d",port);

	err = getaddrinfo(hostname,sport,&hints,&res);
	if(err|| (res==NULL))
	{
		if(res)
			freeaddrinfo(res);
		return -1;
	}
	


	// set non blocking
	if((flags = fcntl(fd, F_GETFL)) < 0) {
		fprintf(stderr, "timeout_connect: unable to get socket flags\n");
		freeaddrinfo(res);
		return -1;
	}
	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		fprintf(stderr, "timeout_connect: unable to put the socket in non-blocking mode\n");
		freeaddrinfo(res);
		return -1;
	}
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	if(mstimeout >= 0) 
	{
		tv.tv_sec = mstimeout / 1000;
		tv.tv_usec = (mstimeout % 1000) * 1000;

		errno = 0;

		if(connect(fd, res->ai_addr, res->ai_addrlen) < 0) 
		{
			if((errno != EWOULDBLOCK) && (errno != EINPROGRESS))
			{
				fprintf(stderr, "timeout_connect: error connecting: %d\n", errno);
				freeaddrinfo(res);
				return -1;
			}
		}
		ret = select(fd+1, NULL, &fds, NULL, &tv);
	}
	freeaddrinfo(res);

	if(ret != 1) 
	{
		if(ret == 0)
			return -1;
		else
			return ret;
	}
	return 0;
}

/********************************************************************************/
int make_tcp_connection_from_port(const char * hostname, unsigned short port,unsigned short sport,int mstimeout)
{
    struct sockaddr_in local;
    int s;
    int err;
    int zero = 0;

    s = socket(AF_INET,SOCK_STREAM,0);
    if(s<0){
        perror("make_tcp_connection: socket");
        exit(1);  // bad socket
    }
    if(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero)) < 0)
    {
        perror("setsockopt");
        fprintf(stderr,"make_tcp_connection::Unable to disable Nagle's algorithm\n");
        exit(1);
    }
    local.sin_family=PF_INET;
    local.sin_addr.s_addr=INADDR_ANY;
    local.sin_port=htons(sport);

    err=bind(s,(struct sockaddr *)&local, sizeof(local));
    if(err)
    {
        perror("make_tcp_connection_from_port::bind");
        return -4;
    }

    err = timeout_connect(s,hostname,port, mstimeout);

    if(err)
    {
        perror("make_tcp_connection: connect");
        close(s);
        return err; // bad connect
    }
    return s;
}

/********************************************************************************/
int make_tcp_connection(const char * hostname, unsigned short port,int mstimeout)
{
    return make_tcp_connection_from_port(hostname,port,INADDR_ANY,mstimeout);
}

/********************************************************************************/
int count_bits(int n)
{
    int count =0;
    int i;
    for(i=0; i< 32;i++)
        if( n & (1<<i))
            count ++;
    return count;
}
/********************************************************************************/
int main(int argc, char * argv[])
{
    char *  controller_hostname = "localhost";
    int     controller_port      = OFP_TCP_PORT;
    struct  fakeswitch *fakeswitches;
    int     n_fakeswitches= 16;
    int     tests_per_loop = 5;
    int     debug = 0;
    int     i,j;
    
    /* parse args here */
    if (argc > 1 ) 
    {
        debug = 1;
        n_fakeswitches=1;
        tests_per_loop=1; 
    }
    fakeswitches = malloc(n_fakeswitches * sizeof(struct fakeswitch));
    assert(fakeswitches);

    for( i = 0; i < n_fakeswitches; i++)
    {
        int sock;
        sock = make_tcp_connection(controller_hostname, controller_port,3000);
        if(sock < 0 )
        {
            fprintf(stderr, "make_nonblock_tcp_connection :: returned %d", sock);
            exit(1);
        }
        if(debug)
            fprintf(stderr,"Initializing switch %d ... ", i+1);
        fflush(stderr);
        fakeswitch_init(&fakeswitches[i],sock,65536, debug);
        if(debug)
            fprintf(stderr," :: done.\n");
        fflush(stderr);
        if(count_bits(i+1) == 1)  // only test for 1,2,4,8,16 switches
            for( j = 0; j < tests_per_loop; j ++)
                run_test(i+1, fakeswitches);
    }

    return 0;
}

