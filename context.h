#ifndef CONTEXT_H
#define CONTEXT_H

struct oflops_context;

#include "oflops.h"
#include "test_module.h"

#include <pcap.h>

typedef struct channel_info {
	char * dev;
	pcap_t * pcap;
	int pcap_fd;	// fd for pcap filter
	int raw_sock;	// raw ethernet access fd
	int sock;	// UDP socket

	int want_pcap;
} channel_info;



typedef struct oflops_context
{
	int n_tests;
	int max_tests;	// size of the tests array
	struct test_module ** tests;
	char * controller_port;
	int listen_fd;
	uint16_t listen_port;
	int snaplen;

	int control_fd;
	int n_channels;
	int max_channels;
	channel_info * channels;	// control, send, recv,etc.
	int should_end;
} oflops_context;

oflops_context * oflops_default_context(void);

int reset_context(oflops_context * ctx);


#endif
