#ifndef TEST_MODULE_H
#define TEST_MODULE_H

#include <openflow/openflow.h>

struct test_module;

#include "oflops.h"
#include "oflops_pcap.h"

enum oflops_channel {
	OFLOPS_CONTROL,		// openflow control channel, e.g., eth0
	OFLOPS_SEND,		// sending channel, e.g., eth1
	OFLOPS_RECV		// recving channel, e.g., eth2
};


// Any test_module can implement any of the following 
// 	functions to override the default behavior

typedef struct test_module
{
	// Ask module what pcap_filter it wants for this channel
	//
	// DEFAULT: return NULL --> don't send pcap events on this channel
	char * (*get_pcap_filter)(oflops_channel ofc);

	// Initialize module with the config string
	//
	// DEFAULT: NOOP
	//
	// return 0 if success, -1 if fatal error
	int (*init)(char * config_str);

	// Tell the module it's time to start its test
	// 	pass raw sockets for send and recv channels
	// 	if the module wants direct access to them
	//
	// DEFAULT: NOOP
	//
	// return 0 if success or -1 to signal module is done
	int (*start)(struct oflops_context * ctx, int send_fd, int recv_fd);

	// Tell the test module that pcap found a packet on 
	// 	a certain channel
	// DEFAULT: ignore pcap events
	// 	if this module does not want pcap events, return NULL
	// 	for get_pcap_filter()
	//
	// return 0 if success or -1 to signal module is done
	int (*pcap_event)(pcap_event * pe);

	// Tell the test module that an openflow mesg came
	// 	over the control channel
	//
	// DEFAULT: ignore this type of openflow message
	//
	// return 0 if success or -1 to signal module is done
	int (*of_event_packet_in)(struct ofp_packet_in * ofph);
	int (*of_event_flow_removed)(struct ofp_flow_removed * ofph);
	int (*of_event_port_status)(struct ofp_port_status * ofph);
	int (*of_event_other)(struct ofp_header * ofph);	

	// Tell the test module that a timer went off
	//
	// DEFAULT: ignore timer events
	//
	// return 0 if success or -1 to signal module is done
	int (*timer_event)(timer_event * te);
	
} test_module;

// List of interfaces exposed from oflops to test_modules


// Send an openflow message from the module to the switch along the control channel
int send_of_mesg(struct oflops_context *ctx, struct ofp_header *);

// Schedule a time event; arg is passed back to the test_module when the event occurs
int schedule_time_event(struct oflops_context *ctx, struct timeval *tv, void * arg);



#endif
