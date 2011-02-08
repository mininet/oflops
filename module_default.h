#ifndef MODULE_DEFAULT_H
#define MODULE_DEFAULT_H

#include "context.h"

/** @defgroup modules
 *
 * Modules for different oflops runs.
 */

// Set of default operations for modules

int default_module_init(struct oflops_context *ctx, char *);
int default_module_destroy(struct oflops_context *ctx);
int default_module_get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen);
int default_module_start(struct oflops_context * ctx);
int default_module_handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch);

int default_module_of_event_packet_in(struct oflops_context *ctx, const struct ofp_packet_in * pktin);

#ifdef HAVE_OFP_FLOW_EXPIRED
	int default_module_of_event_flow_removed(struct oflops_context *ctx, const struct ofp_flow_expired * ofph);
#elif defined(HAVE_OFP_FLOW_REMOVED)
	int default_module_of_event_flow_removed(struct oflops_context *ctx, const struct ofp_flow_removed * ofph);
#else
#error "Unknown version of openflow"
#endif

int default_module_of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph);
int default_module_of_event_port_status(struct oflops_context *ctx, const struct ofp_port_status * ofph);
int default_module_of_event_other(struct oflops_context *ctx, const struct ofp_header * ofph);
int default_module_handle_timer_event(struct oflops_context * ctx, struct timer_event * te);
int default_module_handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se);
int default_module_handle_traffic_generation(struct oflops_context * ctx);

#endif
