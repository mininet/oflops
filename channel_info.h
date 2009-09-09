#ifndef CHANNEL_INFO_H
#define CHANNEL_INFO_H

#include <pcap.h>

typedef struct channel_info {
	char * dev;
	pcap_t * pcap;
	int pcap_fd;	// fd for pcap filter
	int raw_sock;	// raw ethernet access fd
	int sock;	// UDP socket
	int ifindex;	// index of this device

	int want_pcap;
} channel_info;

int channel_info_init(struct channel_info * channel, char * dev);

#endif
