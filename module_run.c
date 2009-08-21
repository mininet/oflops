#include "config.h"
#include <assert.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "module_run.h"
#include "test_module.h"
#include "utils.h"



void setup_channel(oflops_context *ctx, test_module *mod, oflops_channel);


/******************************************************
 * run the test 
 * 	
 */
int run_test_module(oflops_context *ctx, test_module * mod)
{
	mod->start(ctx,ctx->channels[OFLOPS_SEND].raw_sock,
			ctx->channels[OFLOPS_RECV].raw_sock);


	setup_channel( ctx, mod, OFLOPS_CONTROL);
	setup_channel( ctx, mod, OFLOPS_SEND);
	setup_channel( ctx, mod, OFLOPS_RECV);

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
