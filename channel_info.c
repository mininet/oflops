#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include <sys/ioctl.h>
#include <sys/socket.h>


#include "channel_info.h"
#include "utils.h"

int channel_info_init(struct channel_info * channel, char * dev)
{
	struct ifreq ifr;
	int dumb;

	bzero(channel, sizeof(channel_info));
	channel->dev = strdup(dev);
	channel->pcap_fd = -1;
	channel->raw_sock = -1;
	channel->sock = -1;

	/* Not sure why I need a socket to do this */
	dumb = socket(AF_INET, SOCK_STREAM, 0);

	/*retrieve ethernet interface index*/
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (ioctl(dumb, SIOCGIFINDEX, &ifr) == -1) 
		perror_and_exit("SIOCGIFINDEX",1);

	channel->ifindex = ifr.ifr_ifindex;
	channel->packet_len = 0;
    channel->outgoing = msgbuf_new(4096);   // will get resized
	close(dumb);
	return 0;
}

/****************************************************
 * query module if they want pcap and set it up for them if yes
 * also create a raw_socket bound to each device if we have the
 * device set
 */


void setup_channel(oflops_context *ctx, test_module *mod, oflops_channel_name ch )
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
	if( mod->get_pcap_filter(ctx,ch,buf,BUFLEN) <=0)
	{
		fprintf(stderr, "Test %s:  No pcap filter for channel %d on %s\n",
				mod->name(), ch, ch_info->dev);
		ch_info->pcap_handle=NULL;
		return;
	}
	assert(ch_info->dev);		// need to have someting here
	fprintf(stderr,"Test %s:  Starting pcap filter \"%s\" on dev %s for channel %d\n",
			mod->name(), buf, ch_info->dev, ch);
	errbuf[0]=0;
	ch_info->pcap_handle = pcap_open_live(
					ch_info->dev,
					ctx->snaplen,
					1, 	// promisc
					0, 	// read timeout (ms)
					errbuf	// for error messages
			);
	if(!ch_info->pcap_handle)
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

	bzero(&filter, sizeof(filter));
	if(pcap_compile(ch_info->pcap_handle, &filter, buf, 1, net))
	{
		fprintf( stderr, "pcap_compile: %s\n", errbuf);
		exit(1);
	}
	if(strlen(errbuf)>0)
		fprintf( stderr, "Non-fatal pcap_setfilter: %s\n", errbuf);

	if(pcap_setfilter(ch_info->pcap_handle,&filter ) == -1)
	{
		fprintf(stderr,"pcap_setfilter: %s\n",errbuf);
		exit(1);
	}
	if(pcap_setnonblock(ch_info->pcap_handle, 1, errbuf))
		fprintf(stderr,"setup_channel: pcap_setnonblock(): %s\n",errbuf);
	ch_info->pcap_fd = pcap_get_selectable_fd(ch_info->pcap_handle);

}
