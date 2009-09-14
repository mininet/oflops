#ifndef TEST_MODULE_H
#define TEST_MODULE_H

#include <openflow/openflow.h>

struct test_module;

typedef enum oflops_channel_name {
	OFLOPS_CONTROL,		// openflow control channel, e.g., eth0
	OFLOPS_DATA1,		// sending channel, e.g., eth1
	OFLOPS_DATA2, 		// recving channel, e.g., eth2
	OFLOPS_DATA3, 		// recving channel, e.g., eth2
	OFLOPS_DATA4, 		// recving channel, e.g., eth2
	OFLOPS_DATA5, 		// recving channel, e.g., eth2
	OFLOPS_DATA6, 		// recving channel, e.g., eth2
	OFLOPS_DATA7, 		// recving channel, e.g., eth2
	OFLOPS_DATA8, 		// recving channel, e.g., eth2
} oflops_channel_name;

#include "oflops.h"
#include "oflops_pcap.h"
#include "timer_event.h"



// Any test_module can implement any of the following 
// 	functions to override the default behavior

typedef struct test_module
{
	// Return the name of the module
	//
	// DEFAULT: NONE! must be defined
	//
	// str returnned is static; don't free()
	const char * (*name)(void);

	// Initialize module with the config string
	//
	// DEFAULT: NOOP
	//
	// return 0 if success, -1 if fatal error
	int (*init)(struct oflops_context *ctx, char * config_str);

	// Ask module what pcap_filter it wants for this channel
	//
	// DEFAULT: return zero --> don't send pcap events on this channel
	int (*get_pcap_filter)(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen);

	// Tell the module it's time to start its test
	// 	pass raw sockets for send and recv channels
	// 	if the module wants direct access to them
	//
	// DEFAULT: NOOP
	//
	// return 0 if success or -1 on error
	int (*start)(struct oflops_context * ctx);

	// Tell the test module that pcap found a packet on 
	// 	a certain channel
	// DEFAULT: ignore pcap events
	// 	if this module does not want pcap events, return NULL
	// 	for get_pcap_filter()
	//
	// return 0 if success or -1 on error
	int (*handle_pcap_event)(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch);

	// Tell the test module that an openflow mesg came
	// 	over the control channel
	//
	// DEFAULT: ignore this type of openflow message
	//
	// return 0 if success or -1 on error
	int (*of_event_packet_in)(struct oflops_context *ctx, struct ofp_packet_in * ofph);
	#if OFP_VERSION == 0x97
		int (*of_event_flow_removed)(struct oflops_context *ctx, struct ofp_flow_expired * ofph);
	#elif OFP_VERSION == 0x98
		int (*of_event_flow_removed)(struct oflops_context *ctx, struct ofp_flow_removed * ofph);
	#else
		#error "Unknown version of openflow"
	#endif
	int (*of_event_echo_request)(struct oflops_context *ctx, struct ofp_header * ofph);
	int (*of_event_port_status)(struct oflops_context *ctx, struct ofp_port_status * ofph);
	int (*of_event_other)(struct oflops_context *ctx, struct ofp_header * ofph);	

	// Tell the test module that a timer went off
	//
	// DEFAULT: ignore timer events
	//
	// return 0 if success or -1 on error
	int (*handle_timer_event)(struct oflops_context * ctx, struct timer_event * te);
	void * symbol_handle;
	
} test_module;

// List of interfaces exposed from oflops to test_modules


// Send an openflow message from the module to the switch along the control channel
int oflops_send_of_mesg(struct oflops_context *ctx, struct ofp_header *);
// Send an raw message from the module to the switch along the data channel
int oflops_send_raw_mesg(struct oflops_context *ctx, oflops_channel_name ch, void * msg, int len);

// Get the file descriptor of the channel 
int oflops_get_channel_fd(struct oflops_context *ctx, oflops_channel_name ch);
// Get the file descriptor of the channel 
int oflops_get_channel_raw_fd(struct oflops_context *ctx, oflops_channel_name ch);

// Schedule a time event; arg is passed back to the test_module when the event occurs
// 	returns a unique ID for the event (if test wants to cancel it) or -1 on error
int oflops_schedule_timer_event(struct oflops_context *ctx, struct timeval *tv, void * arg);

// Tell the harness this test is over
int oflops_end_test(struct oflops_context *ctx);



#endif
