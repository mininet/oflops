#include "config.h"
#include <assert.h>
#include <dlfcn.h>
#include <pcap.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "module_run.h"
#include "module_default.h"
#include "test_module.h"
#include "utils.h"



static void setup_channel(oflops_context *ctx, test_module *mod, oflops_channel ch);
static void test_module_loop(oflops_context *ctx, test_module *mod);
static void process_event(oflops_context *ctx, test_module * mod, struct pollfd *fd);
static void process_control_event(oflops_context *ctx, test_module * mod, struct pollfd *fd);
static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, oflops_channel ch);


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


static void setup_channel(oflops_context *ctx, test_module *mod, oflops_channel ch )
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
static void test_module_loop(oflops_context *ctx, test_module *mod)
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
				process_event(ctx, mod, &poll_set[i]);
		}
	}
}

/*******************************************************
 * static void process_event(oflops_context *ctx, test_module * mod, struct pollfd *pfd)
 * this channel got an event
 * 	figure out what it is, parse it, and send it to
 * 	the test module
 */


static void process_event(oflops_context *ctx, test_module * mod, struct pollfd *pfd)
{
	// this is inefficient, but ok since there are really only 4 cases
	if(pfd->fd == ctx->control_fd)
		process_control_event(ctx, mod, pfd);
	else if (pfd->fd == ctx->channels[OFLOPS_CONTROL].pcap_fd)
		process_pcap_event(ctx, mod, pfd,OFLOPS_CONTROL);
	else if (pfd->fd == ctx->channels[OFLOPS_SEND].pcap_fd)
		process_pcap_event(ctx, mod, pfd,OFLOPS_SEND);
	else if (pfd->fd == ctx->channels[OFLOPS_RECV].pcap_fd)
		process_pcap_event(ctx, mod, pfd,OFLOPS_RECV);
	else 
	{
		fprintf(stderr, "Event on unknown fd %d .. dying", pfd->fd);
		abort();
	}
}

/***********************************************************************************************
 * static void process_control_event(oflops_context *ctx, test_module * mod, struct pollfd *fd);
 * 	if POLLIN is set, read an openflow message from the control channel
 * 	FIXME: handle a control channel reset here
 */
static void process_control_event(oflops_context *ctx, test_module * mod, struct pollfd *pfd)
{
	// FIXME: this code assumes that the entire message is in the buffer and thus we don't have to buffer
	// partial messages	; buffering is a PITA and I'm just asserting around it here
	char * buf;
	unsigned int msglen;
	struct ofp_header ofph;
	int err;

	assert(pfd->revents & POLLIN);		// FIXME: only know how to handle POLLIN events for now
	// read just the header from the socket
	err = read(pfd->fd,&ofph, sizeof(ofph));
	assert(err == sizeof(ofph));		// FIXME!
	msglen = ntohs(ofph.length);

	buf = malloc_and_check(msglen);
	// copy header into place
	memcpy(buf,&ofph,sizeof(ofph));
	// read the rest of the msg if any
	if( msglen > sizeof(ofph))
	{
		err = read(pfd->fd, &buf[sizeof(ofph)], msglen - sizeof(ofph));
		assert(err == (msglen - sizeof(ofph)));	// make sure we got everything
	}

	switch(ofph.type)
	{
		case OFPT_PACKET_IN:
			mod->of_event_packet_in((struct ofp_packet_in *)buf);
			break;
		case OFPT_FLOW_EXPIRED:
			#if OFP_VERSION == 0x97
				mod->of_event_flow_removed((struct ofp_flow_expired *)buf);
			#elif OFP_VERSION == 0x98
				mod->of_event_flow_removed((struct ofp_flow_removed *)buf);
			#else
			#error "Unknown version of openflow"
			#endif
			break;
		case OFPT_PORT_STATUS:
			mod->of_event_port_status((struct ofp_port_status *)buf);
			break;
		default:
			mod->of_event_other((struct ofp_header * ) buf);
			break;
	};
}


/**********************************************************************************************
 * static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, oflops_channel ch);
 * 	front end to oflops_pcap_handler
 * 		make sure all of the memory is kosher before and after
 * 		pcap's callback thing has always annoyed me
 */
static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, oflops_channel ch)
{
	struct pcap_event_wrapper wrap;
	int count;

	// read the next packet from the appropriate pcap socket
	count = pcap_dispatch(ctx->channels[ch].pcap, 1, oflops_pcap_handler, (u_char *) & wrap);
	// dispatch it to the test module
	mod->pcap_event(wrap.pe, ch);
	// clean up our mess
	pcap_event_free(wrap.pe);
	return;
}
/*************************************************************************
 * int load_test_module(oflops_context *ctx, 
 * 			char * mod_filename, char * initstr);
 * 	open this module and strip symbols out of it
 * 	and call init() on it
 */
int load_test_module(oflops_context *ctx, char * mod_filename, char * initstr)
{
	void * handle;
	test_module * mod;
	mod = malloc_and_check(sizeof(*mod));
	bzero(mod,sizeof(*mod));

	// open module for dyn symbols
	handle = dlopen(mod_filename,RTLD_NOW);
	mod->name = dlsym(handle,"name");
	if(!mod->name)
	{
		fprintf( stderr, "Module %s does not contain a name() function\n", mod_filename);
		free(mod);
		dlclose(handle);
		return 1;	// fail for now
	}

#define symbol_fetch(X) mod->X = dlsym(handle, #X);   if(!mod->X) mod->X = default_module_##X
	symbol_fetch(init);
	symbol_fetch(start);
	symbol_fetch(get_pcap_filter);
	symbol_fetch(pcap_event);
	symbol_fetch(of_event_packet_in);
	symbol_fetch(of_event_flow_removed);
	symbol_fetch(of_event_port_status);
	symbol_fetch(of_event_other);
	symbol_fetch(timer_event);
#undef symbol_fetch
	if(ctx->n_tests >= ctx->max_tests)
	{
		ctx->max_tests *=2;
		ctx->tests = realloc_and_check(ctx->tests, ctx->max_tests * sizeof(struct test_modules *));
	}
	ctx->tests[ctx->n_tests++] = mod;
	dlclose(handle);
	return 0;
}
