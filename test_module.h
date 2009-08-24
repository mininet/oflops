#ifndef TEST_MODULE_H
#define TEST_MODULE_H

#include <openflow/openflow.h>

struct test_module;

typedef enum oflops_channel {
	OFLOPS_CONTROL,		// openflow control channel, e.g., eth0
	OFLOPS_SEND,		// sending channel, e.g., eth1
	OFLOPS_RECV		// recving channel, e.g., eth2
} oflops_channel;

extern char * oflops_channel_names[4];

#include "oflops.h"
#include "oflops_pcap.h"
#include "timer_event.h"



// Any test_module can implement any of the following 
// 	functions to override the default behavior

typedef struct test_module
{
	// Return the name of the module
	//
	// DEFAULT: use the filename of the module
	//
	// str returnned is static; don't free()
	const char * (*name)(void);

	// Initialize module with the config string
	//
	// DEFAULT: NOOP
	//
	// return 0 if success, -1 if fatal error
	int (*init)(char * config_str);

	// Ask module what pcap_filter it wants for this channel
	//
	// DEFAULT: return zero --> don't send pcap events on this channel
	int (*get_pcap_filter)(oflops_channel ofc, char * filter, int buflen);

	// Tell the module it's time to start its test
	// 	pass raw sockets for send and recv channels
	// 	if the module wants direct access to them
	//
	// DEFAULT: NOOP
	//
	// return 0 if success or -1 on error
	int (*start)(struct oflops_context * ctx, int send_fd, int recv_fd);

	// Tell the test module that pcap found a packet on 
	// 	a certain channel
	// DEFAULT: ignore pcap events
	// 	if this module does not want pcap events, return NULL
	// 	for get_pcap_filter()
	//
	// return 0 if success or -1 on error
	int (*pcap_event)(struct pcap_event * pe, oflops_channel ch);

	// Tell the test module that an openflow mesg came
	// 	over the control channel
	//
	// DEFAULT: ignore this type of openflow message
	//
	// return 0 if success or -1 on error
	int (*of_event_packet_in)(struct ofp_packet_in * ofph);
	#if OFP_VERSION == 0x97
		int (*of_event_flow_removed)(struct ofp_flow_expired * ofph);
	#elif OFP_VERSION == 0x98
		int (*of_event_flow_removed)(struct ofp_flow_removed * ofph);
	#else
		#error "Unknown version of openflow"
	#endif
	int (*of_event_port_status)(struct ofp_port_status * ofph);
	int (*of_event_other)(struct ofp_header * ofph);	

	// Tell the test module that a timer went off
	//
	// DEFAULT: ignore timer events
	//
	// return 0 if success or -1 on error
	int (*timer_event)(struct timer_event * te);
	
} test_module;

// List of interfaces exposed from oflops to test_modules


// Send an openflow message from the module to the switch along the control channel
int send_of_mesg(struct oflops_context *ctx, struct ofp_header *);

// Schedule a time event; arg is passed back to the test_module when the event occurs
int schedule_time_event(struct oflops_context *ctx, struct timeval *tv, void * arg);

// Tell the harness this test is over
int end_test(struct oflops_context *ctx);



#endif
