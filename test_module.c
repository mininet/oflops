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

int end_test(struct oflops_context *ctx)
{
	ctx->should_end = 1;
	return 0;
}



int get_channel_raw_fd(struct oflops_context * ctx, oflops_channel ch)
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

int get_channel_fd(struct oflops_context * ctx, oflops_channel ch)
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
