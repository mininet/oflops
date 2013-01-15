#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <getopt.h>
#include <math.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/tcp.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>


#include <openflow/openflow.h>

#include "myargs.h"
#include "cbench.h"
#include "fakeswitch.h"




struct myargs my_options[] = {
    {"controller",  'c', "hostname of controller to connect to", MYARGS_STRING, {.string = "localhost"}},
    {"debug",       'd', "enable debugging", MYARGS_FLAG, {.flag = 0}},
    {"help",        'h', "print this message", MYARGS_NONE, {.none = 0}},
    {"loops",       'l', "loops per test",   MYARGS_INTEGER, {.integer = 16}},
    {"mac-addresses", 'M', "unique source MAC addresses per switch", MYARGS_INTEGER, {.integer = 100000}},
    {"ms-per-test", 'm', "test length in ms", MYARGS_INTEGER, {.integer = 1000}},
    {"port",        'p', "controller port",  MYARGS_INTEGER, {.integer = OFP_TCP_PORT}},
    {"ranged-test", 'r', "test range of 1..$n switches", MYARGS_FLAG, {.flag = 0}},
    {"switches",    's', "fake $n switches", MYARGS_INTEGER, {.integer = 16}},
    {"throughput",  't', "test throughput instead of latency", MYARGS_NONE, {.none = 0}},
    {"warmup",  'w', "loops to be disregarded on test start (warmup)", MYARGS_INTEGER, {.integer = 1}},
    {"cooldown",  'C', "loops to be disregarded at test end (cooldown)", MYARGS_INTEGER, {.integer = 0}},
    {"delay",  'D', "delay starting testing after features_reply is received (in ms)", MYARGS_INTEGER, {.integer = 0}},
    {"connect-delay",  'i', "delay between groups of switches connecting to the controller (in ms)", MYARGS_INTEGER, {.integer = 0}},
    {"connect-group-size",  'I', "number of switches in a connection delay group", MYARGS_INTEGER, {.integer = 1}},
    {"learn-dst-macs",  'L', "send gratuitious ARP replies to learn destination macs before testing", MYARGS_FLAG, {.flag = 1}},
    {"dpid-offset",  'o', "switch DPID offset", MYARGS_INTEGER, {.integer = 1}},
    {0, 0, 0, 0}
};

/*******************************************************************/
double run_test(int n_fakeswitches, struct fakeswitch * fakeswitches, int mstestlen, int delay)
{
    struct timeval now, then, diff;
    struct  pollfd  * pollfds;
    int i;
    double sum = 0;
    double passed;
    int count;

    int total_wait = mstestlen + delay;
    time_t tNow;
    struct tm *tmNow;
    pollfds = malloc(n_fakeswitches * sizeof(struct pollfd));
    assert(pollfds);
    gettimeofday(&then,NULL);
    while(1)
    {
        gettimeofday(&now, NULL);
        timersub(&now, &then, &diff);
        if( (1000* diff.tv_sec  + (float)diff.tv_usec/1000)> total_wait)
            break;
        for(i = 0; i< n_fakeswitches; i++)
            fakeswitch_set_pollfd(&fakeswitches[i], &pollfds[i]);

        poll(pollfds, n_fakeswitches, 1000);      // block until something is ready or 100ms passes

        for(i = 0; i< n_fakeswitches; i++)
            fakeswitch_handle_io(&fakeswitches[i], &pollfds[i]);
    }
    tNow = now.tv_sec;
    tmNow = localtime(&tNow);
    printf("%02d:%02d:%02d.%03d %-3d switches: flows/sec:  ", tmNow->tm_hour, tmNow->tm_min, tmNow->tm_sec, (int)(now.tv_usec/1000), n_fakeswitches);
    usleep(100000); // sleep for 100 ms, to let packets queue
    for( i = 0 ; i < n_fakeswitches; i++)
    {
        count = fakeswitch_get_count(&fakeswitches[i]);
        printf("%d  ", count);
        sum += count;
    }
    passed = 1000 * diff.tv_sec + (double)diff.tv_usec/1000;   
    passed -= delay;        // don't count the time we intentionally delayed
    sum /= passed;  // is now per ms
    printf(" total = %lf per ms \n", sum);
    free(pollfds);
    return sum;
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
int make_tcp_connection_from_port(const char * hostname, unsigned short port, unsigned short sport,
        int mstimeout, int nodelay)
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
    if(nodelay && (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero)) < 0))
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
int make_tcp_connection(const char * hostname, unsigned short port, int mstimeout, int nodelay)
{
    return make_tcp_connection_from_port(hostname,port, INADDR_ANY, mstimeout, nodelay);
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



#define PROG_TITLE "USAGE: cbench [option]  # by Rob Sherwood 2010"

int main(int argc, char * argv[])
{
    struct  fakeswitch *fakeswitches;

    char *  controller_hostname = myargs_get_default_string(my_options,"controller");
    int     controller_port      = myargs_get_default_integer(my_options, "port");
    int     n_fakeswitches= myargs_get_default_integer(my_options, "switches");
    int     total_mac_addresses = myargs_get_default_integer(my_options, "mac-addresses");
    int     mstestlen = myargs_get_default_integer(my_options, "ms-per-test");
    int     should_test_range=myargs_get_default_flag(my_options, "ranged-test");
    int     tests_per_loop = myargs_get_default_integer(my_options, "loops");
    int     debug = myargs_get_default_flag(my_options, "debug");
    int     warmup = myargs_get_default_integer(my_options, "warmup");
    int     cooldown = myargs_get_default_integer(my_options, "cooldown");
    int     delay = myargs_get_default_integer(my_options, "delay");
    int     connect_delay = myargs_get_default_integer(my_options, "connect-delay");
    int     connect_group_size = myargs_get_default_integer(my_options, "connect-group-size");
    int     learn_dst_macs = myargs_get_default_flag(my_options, "learn-dst-macs");
    int     dpid_offset = myargs_get_default_integer(my_options, "dpid-offset");
    int     mode = MODE_LATENCY;
    int     i,j;

    const struct option * long_opts = myargs_to_long(my_options);
    char * short_opts = myargs_to_short(my_options);
    
    /* parse args here */
    while(1)
    {
        int c;
        int option_index=0;
        c = getopt_long(argc, argv, short_opts, long_opts, &option_index);
        if (c == -1)
            break;
        switch (c) 
        {
            case 'c' :  
                controller_hostname = strdup(optarg);
                break;
            case 'd':
                debug = 1;
                break;
            case 'h': 
                myargs_usage(my_options, PROG_TITLE, "help message", NULL, 1);
                break;
            case 'L':
                if(optarg)
                    learn_dst_macs = ( strcasecmp("true", optarg) == 0 || strcasecmp("on", optarg) == 0 || strcasecmp("1", optarg) == 0);
                else
                    learn_dst_macs = 1;
                break;
            case 'l': 
                tests_per_loop = atoi(optarg);
                break;
            case 'M':
                total_mac_addresses = atoi(optarg);
                break;
            case 'm': 
                mstestlen = atoi(optarg);
                break;
            case 'r':
                should_test_range = 1;
                break;
            case 'p' : 
                controller_port = atoi(optarg);
                break;
            case 's': 
                n_fakeswitches = atoi(optarg);
                break;
            case 't': 
                mode = MODE_THROUGHPUT;
                break;
            case 'w': 
                warmup = atoi(optarg);
                break;
            case 'C': 
                cooldown = atoi(optarg);
                break;
            case 'D':
                delay = atoi(optarg);
                break;
            case 'i':
                connect_delay = atoi(optarg);
                break;
            case 'I':
                connect_group_size = atoi(optarg);
                break;
            case 'o':
                dpid_offset = atoi(optarg);
                break;
            default: 
                myargs_usage(my_options, PROG_TITLE, "help message", NULL, 1);
        }
    }

	if(warmup+cooldown >=  tests_per_loop) {
		fprintf(stderr, "Error warmup(%d) + cooldown(%d) >= number of tests (%d)\n", warmup, cooldown, tests_per_loop);
		exit(1);
	}

    fprintf(stderr, "cbench: controller benchmarking tool\n"
                "   running in mode %s\n"
                "   connecting to controller at %s:%d \n"
                "   faking%s %d switches offset %d :: %d tests each; %d ms per test\n"
                "   with %d unique source MACs per switch\n"
                "   %s destination mac addresses before the test\n"
                "   starting test with %d ms delay after features_reply\n"
                "   ignoring first %d \"warmup\" and last %d \"cooldown\" loops\n"
                "   connection delay of %dms per %d switch(es)\n"
                "   debugging info is %s\n",
                mode == MODE_THROUGHPUT? "'throughput'": "'latency'",
                controller_hostname,
                controller_port,
                should_test_range ? " from 1 to": "",
                n_fakeswitches,
                dpid_offset,
                tests_per_loop,
                mstestlen,
                total_mac_addresses,
                learn_dst_macs ? "learning" : "NOT learning",
                delay,
                warmup,cooldown,
                connect_delay,connect_group_size,
                debug == 1 ? "on" : "off");
    /* done parsing args */
    fakeswitches = malloc(n_fakeswitches * sizeof(struct fakeswitch));
    assert(fakeswitches);

    double *results;
    double  min = DBL_MAX;
    double  max = 0.0;
    double  v;
    results = malloc(tests_per_loop * sizeof(double));

    for( i = 0; i < n_fakeswitches; i++)
    {
        int sock;
        double sum = 0;
        if (connect_delay != 0 && i != 0 && (i % connect_group_size == 0)) {
            if(debug)
                fprintf(stderr,"Delaying connection by %dms...", connect_delay*1000);
            usleep(connect_delay*1000);
        }
        sock = make_tcp_connection(controller_hostname, controller_port,3000, mode!=MODE_THROUGHPUT );
        if(sock < 0 )
        {
            fprintf(stderr, "make_nonblock_tcp_connection :: returned %d", sock);
            exit(1);
        }
        if(debug)
            fprintf(stderr,"Initializing switch %d ... ", i+1);
        fflush(stderr);
        fakeswitch_init(&fakeswitches[i],dpid_offset+i,sock,BUFLEN, debug, delay, mode, total_mac_addresses, learn_dst_macs);
        if(debug)
            fprintf(stderr," :: done.\n");
        fflush(stderr);
        if(count_bits(i+1) == 0)  // only test for 1,2,4,8,16 switches
            continue;
        if(!should_test_range && ((i+1) != n_fakeswitches)) // only if testing range or this is last
            continue;
        for( j = 0; j < tests_per_loop; j ++) {
            if ( j > 0 )
                delay = 0;      // only delay on the first run
            v = 1000.0 * run_test(i+1, fakeswitches, mstestlen, delay);
            results[j] = v;
			if(j<warmup || j >= tests_per_loop-cooldown) 
				continue;
            sum += v;
            if (v > max)
              max = v;
            if (v < min)
              min = v;
        }

		int counted_tests = (tests_per_loop - warmup - cooldown);
        // compute std dev
        double avg = sum / counted_tests;
        sum = 0.0;
        for (j = warmup; j < tests_per_loop-cooldown; ++j) {
          sum += pow(results[j] - avg, 2);
        }
        sum = sum / (double)(counted_tests);
        double std_dev = sqrt(sum);

        printf("RESULT: %d switches %d tests "
            "min/max/avg/stdev = %.2lf/%.2lf/%.2lf/%.2lf responses/s\n",
                i+1,
                counted_tests,
                min, max, avg, std_dev);
    }

    return 0;
}

