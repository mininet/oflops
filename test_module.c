#include "config.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "test_module.h"


/***********************************************************************
 * hook for the test module to signal that the test is done
 */

int end_test(struct oflops_context *ctx)
{
	ctx->should_end = 1;
	return 0;
}

/**********************************************************************
 * hook for the test module to get access to a raw file descriptor bound
 * 	to the data channel's device
 */

int get_channel_raw_fd(struct oflops_context * ctx, oflops_channel_name ch)
{
	struct ifreq ifr;
	struct channel_info * ch_info;
	if(ch >= ctx->n_channels)
		return -1;	// no such channel
	ch_info = &ctx->channels[ch];
	if(ch_info->raw_sock != -1)	// already allocated?
		return ch_info->raw_sock;
	// else, setup raw socket
	ch_info->raw_sock = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
	if( ch_info->raw_sock == -1)
		perror_and_exit("raw socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))",1);
	// bind to a specific port
	strncpy(ifr.ifr_name,ch_info->dev,IFNAMSIZ);
	if( ioctl( ch_info->raw_sock, SIOCGIFINDEX, &ifr)  == -1 )
		perror_and_exit("ioctl() bind to dev",1);
	return ch_info->raw_sock;
}

/**********************************************************************
 * hook for the test module to get access to a udp file descriptor bound
 * 	to the data channel's device
 */
int get_channel_fd(struct oflops_context * ctx, oflops_channel_name ch)
{
	struct ifreq ifr;
	struct channel_info * ch_info;
	if(ch >= ctx->n_channels)
		return -1;	// no such channel
	ch_info = &ctx->channels[ch];
	if(ch_info->sock != -1)	// already allocated?
		return ch_info->sock;
	// else, setup raw socket
	ch_info->sock = socket(AF_INET,SOCK_DGRAM,0);	// UDP socket
	if( ch_info->sock == -1)
		perror_and_exit("udp socket(AF_INET,SOCK_DGRAM,0)",1);
	// bind to a specific port
	strncpy(ifr.ifr_name,ch_info->dev,IFNAMSIZ);
	if( ioctl( ch_info->sock, SIOCGIFINDEX, &ifr)  == -1 )
		perror_and_exit("ioctl() bind to dev",1);
	return ch_info->sock;
}

/***************************************************************************
 * hook for the test module to schedule an timer_event to be called back into the module
 */

int schedule_timer_event(struct oflops_context *ctx, struct timeval *tv, void * arg)
{
	return wc_event_add(ctx->timers, NULL, arg, *tv);
}


/*****************************************************************************
 * hook for the test module to send an openflow mesg across the control channel 
 * 	to the switch
 * 	FIXME: assert()'s that the message doesn't block -- if this is a problem
 * 	we need to implement some buffering and mod the select() call to open for
 * 	writing
 */
int send_of_mesg(struct oflops_context *ctx, struct ofp_header *ofph)
{
	int len = ntohs(ofph->length);
	int err;

	err = write(ctx->control_fd, ofph, len);
	if(err<0)
		perror_and_exit("send_of_mesg: write()",1);
	if( err < len)
	{
		fprintf(stderr, "Short write on control channel (%d < %d) -- FIXME!", err, len);
		abort();
	}
	return err;
}

