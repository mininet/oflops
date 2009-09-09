#include <string.h>

#include "module_default.h"

// Set of default operations for modules; just NOOPs

int default_module_init(struct oflops_context *ctx, char * init)
{
	return 0;
}

int default_module_get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, char * filter, int buflen)
{
	return 0;
}


int default_module_start(struct oflops_context * ctx)
{
	return 0;
}


int default_module_handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch)
{
	return 0;
}



int default_module_of_event_packet_in(struct oflops_context *ctx, struct ofp_packet_in * pktin)
{
	return 0;
}



#if OFP_VERSION == 0x97
	int default_module_of_event_flow_removed(struct oflops_context *ctx, struct ofp_flow_expired * ofph)
#elif OFP_VERSION == 0x98
	int default_module_of_event_flow_removed(struct oflops_context *ctx, struct ofp_flow_removed * ofph)
#else
#error "Unknown version of openflow"
#endif
{
	return 0;
}

int default_module_of_event_echo_request(struct oflops_context *ctx, struct ofp_header * ofph)
{
	struct ofp_header resp;
	memcpy(&resp,ofph,sizeof(resp));
	resp.type = OFPT_ECHO_REPLY;
	oflops_send_of_mesg(ctx, &resp);
}


int default_module_of_event_port_status(struct oflops_context * ctx, struct ofp_port_status * ofph)
{
	return 0;
}
int default_module_of_event_other(struct oflops_context * ctx, struct ofp_header * ofph)
{
	return 0;
}
int default_module_handle_timer_event(struct oflops_context * ctx, struct timer_event * te)
{
	return 0;
}
