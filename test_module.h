#ifndef TEST_MODULE_H
#define TEST_MODULE_H

#include <openflow/openflow.h>
#include "config.h"
#include <pcap.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

struct test_module;
	
typedef enum oflops_channel_name {
	OFLOPS_CONTROL = 0,		// openflow control channel, e.g., eth0
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
#include "oflops_snmp.h"

/**  New test_module should implement these call backs.
 * Unimplemeted callbacks fall back to a default behavior.
 */

typedef struct test_module
{
	/** Return the name of the module
	 *
	 * DEFAULT: NONE! must be defined
     *
	 * @return str returned is static; don't free()
	 */
	const char * (*name)(void);

	/** \brief Initialize module with the config string
     *
	 * DEFAULT: NONE! must be defined
     *
	 * @param ctx opaque context
	 * @param config_str string of parameters to pass to module
	 * @return 0 if success, -1 if fatal error
	 */
	int (*init)(struct oflops_context *ctx, char * config_str);


  /** \brief Code to be run after the completion of the 
   *   execution of a module
   *
   * DEFAULT: NONE! must be defined
   *
   * @param ctx opaque context
   * @return 0 if success, -1 if fatal error
   */
  int (*destroy)(struct oflops_context *ctx);
  
  /** \brief Ask module what pcap_filter it wants for this channel
   *
   * DEFAULT: return zero --> don't send pcap events on this channel
   *
   * @param ofc      The oflops channel (data or control) to filter on filter
   * @param filter   A tcpdump-style pcap filter string, suitable for pcap_set_filter()
   *          This string is already allocated.
   * @param buflen   The max length of the filter string
   * @return The length of the filter string: zero implies "do not listen on this channel"
   */
  int (*get_pcap_filter)(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen);
  
  /** \brief Tell the module it's time to start its test
   * 	pass raw sockets for send and recv channels
   * 	if the module wants direct access to them
   *
   * DEFAULT: NOOP
   *
   * @param ctx opaque context
   *
   * @return 0 if success or -1 on error
   */
  int (*start)(struct oflops_context * ctx);

	/** \brief Tell the test module that pcap found a packet on 
	 * 	a certain channel
     *
	 * DEFAULT: ignore pcap events on this channel
     *
	 * 	if this module does not want pcap events, return NULL
	 * 	for get_pcap_filter()
	 *
	 * @param ctx   opaque context
     * @param pe    structure holding packet and pcap timestamp
     * @param ch    which channel this packet arrived on
	 * @return 0    if success or -1 on error
     */
	int (*handle_pcap_event)(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch);

	/** \brief Tell the test module that an openflow mesg came
	 * 	over the control channel
	 *
	 * DEFAULT: ignore this type of openflow message
	 * 
	 * @param ctx   opaque context
     * @param ofph  a pointer to an openflow message; do not free()
	 * @return 0 if success or -1 on error
     */
	int (*of_event_packet_in)(struct oflops_context *ctx, const struct ofp_packet_in * ofph);
	#ifdef HAVE_OFP_FLOW_EXPIRED
		int (*of_event_flow_removed)(struct oflops_context *ctx, const struct ofp_flow_expired * ofph);
	#elif defined(HAVE_OFP_FLOW_REMOVED)
		int (*of_event_flow_removed)(struct oflops_context *ctx, const struct ofp_flow_removed * ofph);
	#else
		#error "Unknown version of openflow"
	#endif
	// FIXME: KK says this should be vector of all openflow messages
	int (*of_event_echo_request)(struct oflops_context *ctx, const struct ofp_header * ofph);
	int (*of_event_port_status)(struct oflops_context *ctx, const struct ofp_port_status * ofph);
	int (*of_event_other)(struct oflops_context *ctx, const struct ofp_header * ofph);	

	/** \brief Tell the test module that a timer went off
	 *
	 * DEFAULT: ignore timer events
	 *
	 * @param ctx   opaque context
     * @param te    a structure holding relevant timer info
	 * @return      0 if success or -1 on error
     */
	int (*handle_timer_event)(struct oflops_context * ctx, struct timer_event * te);
	void * symbol_handle;

	/** \brief Tell the test module that a SNMP reply is received.
	 * 
	 * DEFAULT: Ignore SNMP replies
	 *
	 * @param ctx opqaue context
	 * @param se struct to handle SNMP reply
	 * @return 0 if success and -1 if error
	 */
	int (*handle_snmp_event)(struct oflops_context * ctx, struct snmp_event * se);

	/** \brief run the packet generator module
	 * 
	 * DEFAULT: No packet generation
	 *
	 * @param ctx opqaue context
	 * @return 0 if success and -1 if error
	 */
	int (*handle_traffic_generation)(struct oflops_context * ctx);
	
} test_module;

// List of interfaces exposed from oflops to test_modules

/** Send a buffer of openflow messages from the module to the switch along the control channel
 * @param ctx	opaque pointer
 * @param buf	pointer to an openflow header message (already in network byte order)
 * @param buflen    length of the buffer
 */
size_t oflops_send_of_mesgs(struct oflops_context *ctx, char * buf, size_t buflen);

/** Send an openflow message from the module to the switch along the control channel
 * @param ctx	opaque pointer
 * @param hdr	pointer to an openflow header message (already in network byte order)
 */
int oflops_send_of_mesg(struct oflops_context *ctx, struct ofp_header * hdr);

/** Send an raw message to the switch out a specified channel
 * @param ctx	opaque pointer
 * @param ch  	Oflops channel to send the message out
 * @param msg	pointer to mesg including link layer headers
 * @param len	length of msg
 * @return number of bytes written; -1 if error (same as write(2))
 */
int oflops_send_raw_mesg(struct oflops_context *ctx, oflops_channel_name ch, void * msg, int len);

/** Get a file descriptor for the specified channel 
 * returns an fd of a UDP socket bound to the device bound to the specified channel
 * @param ctx	opaque pointer
 * @param ch  	Oflops channel 
 * @return	file descriptor
 */
int oflops_get_channel_fd(struct oflops_context *ctx, oflops_channel_name ch);

/** Get a file descriptor for the specified channel 
 * returns an fd of a *raw* socket bound to the device bound to the specified channel
 * @param ctx	opaque pointer
 * @param ch  	Oflops channel 
 * @return	file descriptor
 */
int oflops_get_channel_raw_fd(struct oflops_context *ctx, oflops_channel_name ch);

/** Schedule a time event; arg is passed back to the test_module when the event occurs
 * @param ctx	opaque pointer
 * @param tv	a pointer to the absolute time the event should happen
 * @param arg	a parameter to pass to the event
 * @return a unique ID for the event (if test wants to cancel it) or -1 on error
 */
int oflops_schedule_timer_event(struct oflops_context *ctx, struct timeval *tv, void * arg);
// FIXME: expose cancel timmer

/** Lookup the timestamp for this chunk of data 
 * If the specified channel was setup to be tracked via ptrack (pcap_track.h), then
 * it should be possible to map this blob of data to the libpcap timestamp when it came in
 * ptrack_add_* can be used to track openflow messages, tcp messages, etc.
 * @param ctx	opaque pointer
 * @param data 	the data to lookup
 * @param len	length of the data
 * @param hdr	pointer to a pcap header; this will be filled in if the data is matched
 * @return 	zero if not found (*hdr unchanged); >zero implies *hdr is valid and actual number indicates how far oflops had to search
 */
int oflops_get_timestamp(struct oflops_context * ctx, void * data, int len, struct pcap_pkthdr * hdr, oflops_channel_name ofc);

/** Send SNMP get with oid
 * @param ctx opaque pointer
 * @param query oid to request
 * @param len length of oid
 * @return 0 if success and 1 if session fails
 */
int oflops_snmp_get(struct oflops_context * ctx, oid query[], size_t len);

/** Tell the harness this test is over
 * @param ctx	i		opaque pointer
 * @param should_continue	flag for if this test had a fatal error and the oflops suite should stop processing other tests
 * @return zero (always for now)
 */
int oflops_end_test(struct oflops_context *ctx, int should_continue);

#endif
