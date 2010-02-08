#ifndef CHANNEL_INFO_H
#define CHANNEL_INFO_H

struct channel_info;
#include <pcap.h>

#include "context.h"
#include "test_module.h"
#include "pcap_track.h"
#include "msgbuf.h"

typedef struct channel_info {
	char * dev;
	pcap_t * pcap_handle;
	int pcap_fd;	// fd for pcap filter
	int raw_sock;	// raw ethernet access fd
	int sock;	// UDP socket
	int ifindex;	// index of this device
	int packet_len; // length of packet for equally chunked data transfer (0: don't chunk)
	struct ptrack_list * timestamps;
    struct msgbuf * outgoing;
} channel_info;

int channel_info_init(struct channel_info * channel, char * dev);
void setup_channel(struct oflops_context *ctx, struct test_module *mod, enum oflops_channel_name ch);

#endif
