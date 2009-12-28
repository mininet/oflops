#ifndef CONTEXT_H
#define CONTEXT_H

struct oflops_context;

#include "oflops.h"
#include "test_module.h"
#include "wc_event.h"
#include "channel_info.h"
#include "oflops_snmp.h"
#include <pcap.h>

typedef struct oflops_context
{
	int n_tests;
	int max_tests;	// size of the tests array
	struct test_module ** tests;
	struct test_module * curr_test;
	char * controller_port;
	int listen_fd;
	uint16_t listen_port;
	int snaplen;

	int control_fd;
    struct msgbuf * control_outgoing;
	int n_channels;
	int max_channels;
	struct channel_info * channels;	// control, send, recv,etc.
        /** Pointers to SNMP channel
	 */
	struct snmp_channel* snmp_channel_info;
	int should_end;
	int should_continue;
	struct wc_queue * timers;
} oflops_context;

oflops_context * oflops_default_context(void);

int reset_context(oflops_context * ctx);


#endif
