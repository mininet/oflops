#include <string.h>

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
	close(dumb);
	return 0;
}
