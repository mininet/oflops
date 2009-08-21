#include "config.h"
#include <assert.h>
#include <pcap.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "module_run.h"
#include "test_module.h"
#include "utils.h"



void setup_channel(oflops_context *ctx, test_module *mod, oflops_channel);
void test_module_loop(oflops_context *ctx, test_module *mod);
void process_event(oflops_context *ctx, struct pollfd *fd);


/******************************************************
 * setup the test and call the main loop
 * 	
 */
int run_test_module(oflops_context *ctx, test_module * mod)
{
	mod->start(ctx,ctx->channels[OFLOPS_SEND].raw_sock,
			ctx->channels[OFLOPS_RECV].raw_sock);

	setup_channel( ctx, mod, OFLOPS_CONTROL);
	setup_channel( ctx, mod, OFLOPS_SEND);
	setup_channel( ctx, mod, OFLOPS_RECV);

	test_module_loop(ctx,mod);
}


/****************************************************
 * query module if they want pcap and set it up for them if yes
 */


void setup_channel(oflops_context *ctx, test_module *mod, oflops_channel ch )
{
	char buf[BUFLEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	bpf_u_int32 mask=0, net=0;

	channel_info *ch_info = &ctx->channels[ch];	

	ch_info->want_pcap = mod->get_pcap_filter(ch,buf,BUFLEN);
	if(!ch_info->want_pcap)
	{
		fprintf(stderr, "Test %s:  No pcap filter for channel %s\n",
				mod->name(), oflops_channel_names[ch]);
		ch_info->pcap=NULL;
		return;
	}
	assert(ch_info->dev);		// need to have someting here
	fprintf(stderr,"Test %s:  Starting pcap filter \"%s\" on dev %s for channel %s\n",
			mod->name(), buf, ch_info->dev, oflops_channel_names[ch]);
	errbuf[0]=0;
	ch_info->pcap = pcap_open_live(
					ch_info->dev,
					ctx->snaplen,
					1, 	// promisc
					0, 	// read timeout (ms)
					errbuf	// for error messages
			);
	if(!ch_info->pcap)
	{
		fprintf( stderr, "pcap_open_live failed: %s\n",errbuf);
		exit(1);
	}
	if(strlen(errbuf)>0)
		fprintf( stderr, "Non-fatal pcap warning: %s\n", errbuf);
	if((pcap_lookupnet(ch_info->dev,&net,&mask,errbuf) == -1) &&
			(ch == OFLOPS_CONTROL)) 	// only control has an IP
	{
		fprintf(stderr,"WARN: pcap_lookupnet: %s; ",errbuf);
		fprintf(stderr,"filter rules might fail\n");
	}

	if(pcap_compile(ch_info->pcap, &filter, buf, 1, net))
	{
		fprintf( stderr, "pcap_compile: %s\n", errbuf);
		exit(1);
	}

	if(pcap_setfilter(ch_info->pcap,&filter ) == -1)
	{
		fprintf(stderr,"pcap_setfilter: %s\n",errbuf);
		exit(1);
	}

}


/********************************************************
 * main loop()
 * 	1) setup poll
 * 	2) call poll with a min timeout of the next event
 * 	3) dispatch events as appropriate
 */
void test_module_loop(oflops_context *ctx, test_module *mod)
{
	struct pollfd poll_set[4];
	int ret;

	bzero(poll_set,sizeof(4 * sizeof(struct pollfd)));

	poll_set[OFLOPS_CONTROL].fd = ctx->channels[OFLOPS_CONTROL].pcap_fd;
	poll_set[OFLOPS_SEND].fd = ctx->channels[OFLOPS_SEND].pcap_fd;
	poll_set[OFLOPS_RECV].fd = ctx->channels[OFLOPS_RECV].pcap_fd;
	poll_set[3].fd = ctx->control_fd;

	// look for pcap events if the module wants them
	if(ctx->channels[OFLOPS_CONTROL].pcap)
		poll_set[OFLOPS_CONTROL].events = POLLIN;
	if(ctx->channels[OFLOPS_SEND].pcap)
		poll_set[OFLOPS_SEND].events = POLLIN;
	if(ctx->channels[OFLOPS_RECV].pcap)
		poll_set[OFLOPS_RECV].events = POLLIN;
	// always listen to openflow control channel messages
	poll_set[3].events = POLLIN;		

	ctx->should_end = 0;
	while(!ctx->should_end)
	{
		int next_event;
		
		while(next_event <= 0 )
			timer_run_next_event(ctx);
		next_event = timer_get_next_event(ctx);
		ret = poll(poll_set, 4, next_event);

		if(( ret == -1 ) && ( errno != EINTR))
			perror_and_exit("poll",1);
		else if(ret == 0 )
			timer_run_next_event(ctx);
		else // found something to read
		{
			int i;	
			for(i=0; i<ret; i++)
				process_event(ctx, &poll_set[i]);
		}
	}
}

/*******************************************************
 * this channel got an event
 * 	figure out what it is, parse it, and send it to
 * 	the test module
 */


void process_event(oflops_context *ctx, struct pollfd *fd)
{
	// FIXME
	abort();

}
