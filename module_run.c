#include "config.h"
#include <assert.h>
#include <dlfcn.h>
#include <pcap.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>


#include "module_run.h"
#include "module_default.h"
#include "test_module.h"
#include "utils.h"



static void setup_channel(oflops_context *ctx, test_module *mod, oflops_channel_name ch);
static void test_module_loop(oflops_context *ctx, test_module *mod);
static void process_event(oflops_context *ctx, test_module * mod, struct pollfd *fd);
static void process_control_event(oflops_context *ctx, test_module * mod, struct pollfd *fd);
static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, oflops_channel_name ch);


/******************************************************
 * setup the test and call the main loop
 * 	
 */
int run_test_module(oflops_context *ctx, test_module * mod)
{
	int i;
	for(i=0;i<ctx->n_channels;i++)
		setup_channel( ctx, mod, i);

	mod->start(ctx);

	test_module_loop(ctx,mod);
}


/****************************************************
 * query module if they want pcap and set it up for them if yes
 * also create a raw_socket bound to each device if we have the
 * device set
 */


static void setup_channel(oflops_context *ctx, test_module *mod, oflops_channel_name ch )
{
	char buf[BUFLEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	bpf_u_int32 mask=0, net=0;

	channel_info *ch_info = &ctx->channels[ch];	

	if(ch_info->dev==NULL)	// no device specified
	{
		ch_info->dev = pcap_lookupdev(errbuf);
		fprintf(stderr,"%s channel %i not configured; guessing device: ",
				((ch==OFLOPS_CONTROL)?"Control":"Data"), ch);
		if(ch_info->dev)
			fprintf(stderr,"%s",ch_info->dev);
		else
		{
			fprintf(stderr, " pcap_lookup() failed: %s ; exiting....\n", errbuf);
			exit(1);
		}
	}

	// setup pcap filter, if wanted
	ch_info->want_pcap = mod->get_pcap_filter(ctx,ch,buf,BUFLEN);
	if(!ch_info->want_pcap)
	{
		fprintf(stderr, "Test %s:  No pcap filter for channel %d on %s\n",
				mod->name(), ch, ch_info->dev);
		ch_info->pcap=NULL;
		return;
	}
	assert(ch_info->dev);		// need to have someting here
	fprintf(stderr,"Test %s:  Starting pcap filter \"%s\" on dev %s for channel %d\n",
			mod->name(), buf, ch_info->dev, ch);
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
	struct pollfd * poll_set;
	int ret;
	int len; 
	int ch;
	int n_channels=0;

	len = sizeof(struct pollfd) * (ctx->n_channels + 1);
	poll_set = malloc_and_check(len);

	while(!ctx->should_end)
	{
		int next_event;
		n_channels=0;
		bzero(poll_set,len);

		for(ch=0; ch< ctx->n_channels; ch++)
		{
			if( ctx->channels[ch].pcap)
			{
				poll_set[n_channels].fd = ctx->channels[ch].pcap_fd;
				poll_set[n_channels].events = POLLIN;
				n_channels++;
			}
		}
		poll_set[n_channels].fd = ctx->control_fd;	// add the control channel at the end
		poll_set[n_channels].events = POLLIN;
		n_channels++;
		
		next_event = timer_get_next_event(ctx);
		while(next_event <= 0 )
		{
			timer_run_next_event(ctx);
			next_event = timer_get_next_event(ctx);
		}
		ret = poll(poll_set, n_channels, next_event);

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
 * a channel got an event
 * 	map the event to the correct channel, and call the appropriate event handler
 *
 * 	FIXME: for efficency, we really should have a faster fd-> channel map, but 
 * 		since the number of channels is small, we can just be fugly
 */


static void process_event(oflops_context *ctx, test_module * mod, struct pollfd *pfd)
{
	int ch;
	if(pfd->fd == ctx->control_fd)
		return process_control_event(ctx, mod, pfd);
	// this is inefficient, but ok since there are really typically only ~8  cases
	for(ch=0; ch< ctx->n_channels; ch++)
		if (pfd->fd == ctx->channels[ch].pcap_fd)
			return process_pcap_event(ctx, mod, pfd,ch);
	// only get here if we've screwed up somehow
	fprintf(stderr, "Event on unknown fd %d .. dying", pfd->fd);
	abort();
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
	if(err < 0)
	{
		perror("process_control_event:read() ::");
		return ;
	}
	if(err == 0)
	{
		fprintf(stderr, "Switch Control Connection reset! wtf!?!...exiting\n");
		exit(0);
	}
	if(err <  sizeof(ofph))		// FIXME!
	{
		fprintf(stderr, "process_control_event:read(): short read (%d < %u)\n",
				err, sizeof(ofph));
		abort();
		return;

	}
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
			mod->of_event_packet_in(ctx, (struct ofp_packet_in *)buf);
			break;
		case OFPT_FLOW_EXPIRED:
			#if OFP_VERSION == 0x97
				mod->of_event_flow_removed(ctx, (struct ofp_flow_expired *)buf);
			#elif OFP_VERSION == 0x98
				mod->of_event_flow_removed(ctx, (struct ofp_flow_removed *)buf);
			#else
			#error "Unknown version of openflow"
			#endif
			break;
		case OFPT_PORT_STATUS:
			mod->of_event_port_status(ctx, (struct ofp_port_status *)buf);
			break;
		case OFPT_ECHO_REQUEST:
			mod->of_event_echo_request(ctx, (struct ofp_header *)buf);
			break;
		default:
			mod->of_event_other(ctx, (struct ofp_header * ) buf);
			break;
	};
}


/**********************************************************************************************
 * static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, oflops_channel_name ch);
 * 	front end to oflops_pcap_handler
 * 		make sure all of the memory is kosher before and after
 * 		pcap's callback thing has always annoyed me
 */
static void process_pcap_event(oflops_context *ctx, test_module * mod, struct pollfd *fd, oflops_channel_name ch)
{
	struct pcap_event_wrapper wrap;
	int count;

	// read the next packet from the appropriate pcap socket
	count = pcap_dispatch(ctx->channels[ch].pcap, 1, oflops_pcap_handler, (u_char *) & wrap);
	// dispatch it to the test module
	mod->pcap_event(ctx, wrap.pe, ch);
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
	if(handle == NULL)
	{	
		fprintf(stderr,"Error reading symbols from %s : %s\n",
				mod_filename, dlerror());
		return 1;
	}
	mod->name = dlsym(handle,"name");
	mod->start = dlsym(handle,"start");
	if(!mod->name)
		fprintf( stderr, "Module %s does not contain a name() function\n", mod_filename);
	if(!mod->start)
		fprintf( stderr, "Module %s does not contain a start() function\n", mod_filename);
	if(!mod->name || !mod->start)
	{
		free(mod);
		dlclose(handle);
		return 1;	// fail for now
	}

#define symbol_fetch(X) \
	mod->X = dlsym(handle, #X);   \
	if(!mod->X) \
		mod->X = default_module_##X
	symbol_fetch(init);
	symbol_fetch(get_pcap_filter);
	symbol_fetch(pcap_event);
	symbol_fetch(of_event_packet_in);
	symbol_fetch(of_event_flow_removed);
	symbol_fetch(of_event_echo_request);
	symbol_fetch(of_event_port_status);
	symbol_fetch(of_event_other);
	symbol_fetch(handle_timer_event);
#undef symbol_fetch
	if(ctx->n_tests >= ctx->max_tests)
	{
		ctx->max_tests *=2;
		ctx->tests = realloc_and_check(ctx->tests, ctx->max_tests * sizeof(struct test_modules *));
	}
	ctx->tests[ctx->n_tests++] = mod;
	mod->symbol_handle=handle;
	return 0;
}
